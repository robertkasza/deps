package fixcmd

import (
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"sync"

	"github.com/robertkasza/deps/internal/pkgmgr"
	"github.com/robertkasza/deps/internal/plan"
	"github.com/robertkasza/deps/internal/pnpm"
	"github.com/robertkasza/deps/internal/registry"
	"github.com/robertkasza/deps/internal/triage"
)

// defaultConcurrency limits parallel pnpm audit calls to keep us under
// npm's rate limit. See checkcmd for the same default.
const defaultConcurrency = 3

type Options struct {
	Dir         string
	Severity    string
	Concurrency int
}

// Run executes the full check -> apply -> install -> verify pipeline.
//
// Exit codes (returned via exitErr):
//
//	0   all targeted advisories resolved (or nothing to do)
//	10  fix succeeded but unresolved findings remain (no-fix / major-jump)
//	20  some targeted advisories still present after re-audit
//	1   tool error (install failed, write error, ...)
func Run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("fix", flag.ContinueOnError)
	fs.SetOutput(stderr)

	opts := Options{}
	fs.StringVar(&opts.Dir, "dir", ".", "monorepo root (directory containing pnpm-workspace.yaml)")
	fs.StringVar(&opts.Severity, "severity", "moderate", "minimum severity to act on (low|moderate|high|critical)")
	fs.IntVar(&opts.Concurrency, "concurrency", defaultConcurrency, "max workspaces audited in parallel")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}

	pm := pnpm.New()
	fmt.Fprintln(stderr, "discovering workspaces...")
	workspaces, err := pm.DiscoverWorkspaces(opts.Dir)
	if err != nil {
		return fmt.Errorf("discover workspaces: %w", err)
	}

	rootDir := monorepoRoot(workspaces, opts.Dir)

	reg := registry.New()
	planner := plan.New(reg)
	configureCooldownRung(planner, pm, rootDir, stderr)

	// Phase 1: produce the plan (audit + triage + plan per workspace).
	fmt.Fprintf(stderr, "auditing %d workspace(s) (concurrency=%d)...\n",
		len(workspaces), opts.Concurrency)
	results := processAll(pm, planner, workspaces, opts.Concurrency, stderr)

	totalActionable, totalUnresolved, failedCount := summarize(results)
	fmt.Fprintf(stderr,
		"plan: %d actionable finding(s), %d unresolved, %d failure(s)\n",
		totalActionable, totalUnresolved, failedCount)

	if failedCount > 0 {
		return exitErr{code: 1, msg: fmt.Sprintf("%d workspace(s) failed before apply", failedCount)}
	}
	if totalActionable == 0 {
		fmt.Fprintln(stderr, "nothing to apply")
		if totalUnresolved > 0 {
			return exitErr{code: 10}
		}
		return nil
	}

	// Phase 2: apply edits.
	allEdits, targetedGHSAs, editedWorkspaces, cooldownDirs, hasOverride := flatten(results)
	fmt.Fprintf(stderr, "applying %d candidate edit(s)...\n", len(allEdits))
	applied, err := pm.ApplyEdits(allEdits)
	if err != nil {
		return exitErr{code: 1, msg: fmt.Sprintf("apply edits: %v", err)}
	}

	// Phase 3a: trigger lockfile re-resolution for any workspace
	// that received a cooldown-bypass edit. Plain `pnpm install`
	// ignores fresh minimumReleaseAgeExclude entries — the resolver
	// considers the lockfile "already up to date" and skips. `pnpm
	// audit --fix update` is the only command that re-resolves
	// against the new exclude list. cooldownDirs is a minimum set
	// cover of workspaces that collectively include every unique
	// cooldown-bypass package.
	for _, wsDir := range cooldownDirs {
		fmt.Fprintf(stderr, "running pnpm audit --fix update in %s...\n", wsDir)
		if err := pm.AuditFixUpdate(wsDir); err != nil {
			return exitErr{code: 1, msg: fmt.Sprintf("pnpm audit --fix update failed: %v", err)}
		}
	}

	// Phase 3b: regenerate the lockfile for bumps and overrides.
	fmt.Fprintf(stderr, "running pnpm install in %s...\n", rootDir)
	if err := pm.Install(rootDir); err != nil {
		return exitErr{code: 1, msg: fmt.Sprintf("pnpm install failed: %v", err)}
	}

	// Phase 4: re-audit. Per SKILL.md: scoped to edited workspaces
	// for bumps; full repo when any override was added (overrides are
	// global, so they can affect untouched workspaces).
	verifyScope := workspaces
	if !hasOverride {
		verifyScope = filterWorkspaces(workspaces, editedWorkspaces)
	}
	fmt.Fprintf(stderr, "re-auditing %d workspace(s)...\n", len(verifyScope))
	verify := processAll(pm, planner, verifyScope, opts.Concurrency, stderr)
	stillPresent := stillPresentGHSAs(verify, targetedGHSAs)

	// Final report. Three distinct buckets the user needs to see:
	// (1) what we applied and verified, (2) what we tried but failed
	// to clear, (3) what we deliberately did NOT try (unresolved).
	fmt.Fprintf(stderr, "\nfix complete:\n")
	fmt.Fprintf(stderr, "  %d edit(s) applied:\n", len(applied))
	printApplied(stderr, applied, rootDir)

	if len(stillPresent) > 0 {
		fmt.Fprintf(stderr, "  %d advisory(ies) still present after re-audit (apply did not clear them):\n",
			len(stillPresent))
		for _, ghsa := range stillPresent {
			fmt.Fprintf(stderr, "    - %s\n", ghsa)
		}
	}

	if totalUnresolved > 0 {
		fmt.Fprintf(stderr, "  %d advisory(ies) need your attention (deps did not auto-fix):\n",
			totalUnresolved)
		printUnresolved(stderr, results)
	}

	if len(stillPresent) == 0 && totalUnresolved == 0 {
		fmt.Fprintln(stderr, "  all targeted advisories resolved")
	}

	switch {
	case len(stillPresent) > 0:
		return exitErr{code: 20}
	case totalUnresolved > 0:
		return exitErr{code: 10}
	}
	return nil
}

// printApplied prints one line per edit that was actually written to
// disk (post-coalesce). Locations are shown relative to rootDir.
func printApplied(w io.Writer, applied []pkgmgr.Edit, rootDir string) {
	for _, e := range applied {
		loc := editLocation(e.File, rootDir)
		switch e.Kind {
		case pkgmgr.EditBumpDirect, pkgmgr.EditBumpParent:
			fmt.Fprintf(w, "    %s  %s  %s -> %s  (%s)  in %s\n",
				e.Kind, e.Package, e.From, e.To, e.Field, loc)
		case pkgmgr.EditOverrideAdd, pkgmgr.EditOverrideConsolidate:
			fmt.Fprintf(w, "    override     %s@%s -> %s  in %s\n",
				e.Package, e.VulnerableRange, e.To, loc)
			if e.RejectionNotes != "" {
				fmt.Fprintf(w, "                 (%s)\n", e.RejectionNotes)
			}
		case pkgmgr.EditExcludeFromCooldown:
			fmt.Fprintf(w, "    cooldown-bypass  %s@%s  in %s\n",
				e.Package, e.To, loc)
		default:
			fmt.Fprintf(w, "    %s  %+v\n", e.Kind, e)
		}
	}
}

// editLocation returns a human-readable workspace path for an edit's
// target file: the package.json's parent dir relative to rootDir, or
// "<root>" when the edit lives in the monorepo root's package.json.
func editLocation(file, rootDir string) string {
	dir := filepath.Dir(file)
	rel, err := filepath.Rel(rootDir, dir)
	if err != nil || rel == "" || rel == "." {
		return "<root>"
	}
	return rel
}

func printUnresolved(w io.Writer, results []WorkspaceResult) {
	for _, r := range results {
		if r.Err != nil {
			continue
		}
		for _, u := range r.Plan.Unresolved {
			a := u.Finding.Advisory
			fmt.Fprintf(w, "    - %s  %s  %s  (%s)  in %s\n",
				a.GHSA, a.Package, a.Severity, u.Reason, workspaceLabel(r.Workspace))
		}
	}
}

func workspaceLabel(ws pkgmgr.Workspace) string {
	if ws.IsRoot {
		return "<root>"
	}
	if ws.RelDir != "" {
		return ws.RelDir
	}
	if ws.Name != "" {
		return ws.Name
	}
	return "<unnamed>"
}

// WorkspaceResult mirrors checkcmd.WorkspaceResult but is local to
// fixcmd to avoid an import cycle and keep the two commands' display
// concerns independent.
type WorkspaceResult struct {
	Workspace pkgmgr.Workspace
	Findings  []pkgmgr.Finding
	Plan      pkgmgr.Plan
	Err       error
}

func processAll(
	pm pkgmgr.PkgManager,
	planner *plan.Builder,
	workspaces []pkgmgr.Workspace,
	concurrency int,
	progress io.Writer,
) []WorkspaceResult {
	if concurrency < 1 {
		concurrency = 1
	}
	results := make([]WorkspaceResult, len(workspaces))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var (
		progressMu sync.Mutex
		done       int
		total      = len(workspaces)
	)

	report := func(ws pkgmgr.Workspace, err error) {
		progressMu.Lock()
		defer progressMu.Unlock()
		done++
		label := workspaceLabel(ws)
		if err != nil {
			fmt.Fprintf(progress, "  x %s (%d/%d): %v\n", label, done, total, err)
		} else {
			fmt.Fprintf(progress, "  o %s (%d/%d)\n", label, done, total)
		}
	}

	for i, ws := range workspaces {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, ws pkgmgr.Workspace) {
			defer wg.Done()
			defer func() { <-sem }()
			advs, err := pm.Audit(ws)
			if err != nil {
				results[i] = WorkspaceResult{Workspace: ws, Err: err}
				report(ws, err)
				return
			}
			findings, err := triage.Run(advs)
			if err != nil {
				results[i] = WorkspaceResult{Workspace: ws, Err: err}
				report(ws, err)
				return
			}
			p, err := planner.Build(findings)
			if err != nil {
				results[i] = WorkspaceResult{Workspace: ws, Findings: findings, Err: err}
				report(ws, err)
				return
			}
			results[i] = WorkspaceResult{Workspace: ws, Findings: findings, Plan: p}
			report(ws, nil)
		}(i, ws)
	}
	wg.Wait()
	return results
}

func summarize(results []WorkspaceResult) (actionable, unresolved, failed int) {
	for _, r := range results {
		if r.Err != nil {
			failed++
			continue
		}
		actionable += len(r.Plan.Actionable)
		unresolved += len(r.Plan.Unresolved)
	}
	return
}

// flatten gathers actionable edits, the set of GHSAs we tried to
// resolve, the workspaces that received any edit, and whether an
// override-add was issued. The last two drive scoped vs repo-wide
// re-audit (per SKILL.md: scoped is enough for bumps; overrides are
// global so the whole repo must be re-checked).
func flatten(results []WorkspaceResult) (
	edits []pkgmgr.Edit,
	targetedGHSAs map[string]bool,
	editedWorkspaces map[string]bool,
	cooldownDirs []string,
	hasOverride bool,
) {
	targetedGHSAs = map[string]bool{}
	editedWorkspaces = map[string]bool{}
	// cooldownPkgsByWS[workspaceDir] = set of cooldown-bypass package
	// names emitted in that workspace's plan. Used to compute a
	// minimum set cover so that pnpm audit --fix update runs in as
	// few workspaces as possible while still touching every unique
	// package.
	cooldownPkgsByWS := map[string]map[string]bool{}
	for _, r := range results {
		if r.Err != nil {
			continue
		}
		if len(r.Plan.Actionable) > 0 {
			editedWorkspaces[r.Workspace.Dir] = true
		}
		for _, e := range r.Plan.Actionable {
			edits = append(edits, e)
			if e.Kind == pkgmgr.EditOverrideAdd || e.Kind == pkgmgr.EditOverrideConsolidate {
				hasOverride = true
			}
			if e.Kind == pkgmgr.EditExcludeFromCooldown {
				if cooldownPkgsByWS[r.Workspace.Dir] == nil {
					cooldownPkgsByWS[r.Workspace.Dir] = map[string]bool{}
				}
				cooldownPkgsByWS[r.Workspace.Dir][e.Package] = true
			}
		}
		for _, f := range r.Findings {
			if !inUnresolved(f, r.Plan.Unresolved) {
				targetedGHSAs[f.Advisory.GHSA] = true
			}
		}
	}
	cooldownDirs = greedySetCover(cooldownPkgsByWS)
	// Overrides target the monorepo root, so multiple workspaces all
	// emitting an override for the same vuln pkg must collapse to one
	// entry. Per-workspace mergeOverrides inside Build can't see this.
	edits = pkgmgr.MergeOverrides(edits)
	return edits, targetedGHSAs, editedWorkspaces, cooldownDirs, hasOverride
}

// greedySetCover picks the minimum set of workspace dirs (a greedy
// approximation; set cover is NP-hard) needed to "touch" every unique
// cooldown-bypass package name. Running `pnpm audit --fix update` in
// a chosen workspace will refresh every package vulnerable in that
// workspace across the rest of the tree (per pnpm's documented
// behavior); picking the workspace with the largest uncovered
// coverage at each step minimizes invocations.
//
// Returned dirs are sorted by selection order. Empty input yields nil.
func greedySetCover(pkgsByWS map[string]map[string]bool) []string {
	universe := map[string]bool{}
	for _, pkgs := range pkgsByWS {
		for p := range pkgs {
			universe[p] = true
		}
	}
	if len(universe) == 0 {
		return nil
	}
	var picked []string
	for len(universe) > 0 {
		bestWS := ""
		bestCover := 0
		for ws, pkgs := range pkgsByWS {
			cover := 0
			for p := range pkgs {
				if universe[p] {
					cover++
				}
			}
			// Tie-break by workspace dir for determinism.
			if cover > bestCover || (cover == bestCover && cover > 0 && (bestWS == "" || ws < bestWS)) {
				bestCover = cover
				bestWS = ws
			}
		}
		if bestWS == "" {
			break // shouldn't happen — universe was non-empty and pkgsByWS covers it
		}
		picked = append(picked, bestWS)
		for p := range pkgsByWS[bestWS] {
			delete(universe, p)
		}
		delete(pkgsByWS, bestWS)
	}
	return picked
}

func inUnresolved(f pkgmgr.Finding, unresolved []pkgmgr.Unresolved) bool {
	for _, u := range unresolved {
		if u.Finding.Advisory.GHSA == f.Advisory.GHSA &&
			u.Finding.Advisory.Workspace.PackageJSON == f.Advisory.Workspace.PackageJSON {
			return true
		}
	}
	return false
}

// stillPresentGHSAs returns the targeted GHSAs still surfaced by
// post-apply re-audit, sorted for deterministic output.
func stillPresentGHSAs(verify []WorkspaceResult, targeted map[string]bool) []string {
	seen := map[string]bool{}
	for _, r := range verify {
		if r.Err != nil {
			continue
		}
		for _, f := range r.Findings {
			if targeted[f.Advisory.GHSA] {
				seen[f.Advisory.GHSA] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// filterWorkspaces returns only those workspaces whose Dir is in the
// keep set. Used to scope the post-install re-audit to workspaces that
// actually received edits (per SKILL.md verification rules).
func filterWorkspaces(all []pkgmgr.Workspace, keep map[string]bool) []pkgmgr.Workspace {
	if len(keep) == 0 {
		return nil
	}
	out := make([]pkgmgr.Workspace, 0, len(keep))
	for _, ws := range all {
		if keep[ws.Dir] {
			out = append(out, ws)
		}
	}
	return out
}

func monorepoRoot(workspaces []pkgmgr.Workspace, fallback string) string {
	for _, ws := range workspaces {
		if ws.IsRoot {
			return ws.Dir
		}
	}
	return fallback
}

// exitErr signals a specific exit code. main.go unwraps it.
type exitErr struct {
	code int
	msg  string
}

func (e exitErr) Error() string {
	if e.msg != "" {
		return e.msg
	}
	return ""
}

func (e exitErr) Code() int { return e.code }

// configureCooldownRung wires the cooldown-bypass remediation into
// planner. The TreeInspector lazily parses each workspace's own
// pnpm-lock.yaml on demand — correct for both sharedWorkspaceLockfile
// true (every workspace resolves to the same root file, cached) and
// false (per-workspace lockfiles). Cooldown activity is detected once
// from the root pnpm-workspace.yaml + pnpm version.
//
// Failures in cooldown activity detection log to stderr but never
// abort the run; the rung is optional and falling through to
// override-add is always a valid plan.
func configureCooldownRung(planner *plan.Builder, pm *pnpm.Adapter, rootDir string, stderr io.Writer) {
	active, err := pm.CooldownActive(rootDir)
	if err != nil {
		fmt.Fprintf(stderr, "cooldown rung disabled: probe failed (%v)\n", err)
		return
	}
	planner.Tree = pnpm.NewWorkspaceLockfiles()
	planner.CooldownActive = active
	if !active {
		fmt.Fprintln(stderr, "cooldown rung: minimumReleaseAge not active; bypass remediation disabled")
	}
}
