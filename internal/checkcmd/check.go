package checkcmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/robertkasza/deps/internal/auditci"
	"github.com/robertkasza/deps/internal/pkgmgr"
	"github.com/robertkasza/deps/internal/plan"
	"github.com/robertkasza/deps/internal/pnpm"
	"github.com/robertkasza/deps/internal/registry"
	"github.com/robertkasza/deps/internal/triage"
)

// defaultConcurrency limits parallel pnpm audit calls to keep us under
// npm's rate limit (per-IP). Most monorepos are well-served by 3; very
// large ones can raise it via --concurrency.
const defaultConcurrency = 3

type Options struct {
	Dir         string
	Severity    string
	JSON        bool
	Concurrency int
	AllowMajor  bool
}

func Run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)

	opts := Options{}
	fs.StringVar(&opts.Dir, "dir", ".", "monorepo root (directory containing pnpm-workspace.yaml)")
	fs.StringVar(&opts.Severity, "severity", "moderate", "minimum severity to report (low|moderate|high|critical)")
	fs.BoolVar(&opts.JSON, "json", false, "emit machine-readable JSON to stdout")
	fs.IntVar(&opts.Concurrency, "concurrency", defaultConcurrency, "max workspaces audited in parallel")
	fs.BoolVar(&opts.AllowMajor, "allow-major", false, "allow cooldown-bypass to install a fixed version outside an importer's declared range (e.g. a major jump, matching `pnpm audit --fix update`)")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}

	return run(opts, stdout, stderr, pnpm.New(), registry.New())
}

// run accepts external dependencies so command tests do not require pnpm or
// network access.
func run(opts Options, stdout, stderr io.Writer, pm *pnpm.Adapter, reg registry.Client) error {
	pm = pm.WithWarnWriter(stderr)
	fmt.Fprintln(stderr, "discovering workspaces...")
	workspaces, err := pm.DiscoverWorkspaces(opts.Dir)
	if err != nil {
		return fmt.Errorf("discover workspaces: %w", err)
	}

	// All discovered workspaces share the same MonorepoRoot — the real
	// pnpm workspace root (which may be an ancestor of opts.Dir when
	// invoked from inside a member). Shared config, install, and cooldown
	// detection all anchor here, not at opts.Dir.
	rootDir := opts.Dir
	if len(workspaces) > 0 && workspaces[0].MonorepoRoot != "" {
		rootDir = workspaces[0].MonorepoRoot
	}

	allowlist, err := auditci.Load(rootDir)
	if err != nil {
		return err
	}

	planner := plan.New(reg)
	planner.AllowMajor = opts.AllowMajor
	configureCooldownRung(planner, pm, rootDir, stderr)

	fmt.Fprintf(stderr, "auditing %d workspace(s) (concurrency=%d)...\n",
		len(workspaces), opts.Concurrency)
	results := processAll(pm, planner, allowlist, workspaces, opts.Concurrency, stderr)

	// Apply --severity once, here. summarize/exit-code, the stderr summary
	// line, stdout text and JSON output must all agree on the same set of
	// findings — otherwise `deps check --severity critical` on a moderate-
	// only plan can show "no findings" while still exiting 10.
	results = filterResultsBySeverity(results, minSeverity(opts.Severity))

	totalActionable, totalUnresolved, failedCount := summarize(results)
	fmt.Fprintf(stderr,
		"checked %d workspace(s) under %s: %d actionable, %d unresolved, %d failure(s)\n",
		len(results), rootDir, totalActionable, totalUnresolved, failedCount)

	if opts.JSON {
		if err := writeJSON(stdout, rootDir, results); err != nil {
			return err
		}
	} else {
		printResults(stdout, results)
	}

	return decideExit(totalActionable, totalUnresolved, failedCount)
}

// decideExit maps per-workspace counts to the check command's exit
// code contract: tool error > findings present > clean. Code 20
// (`unresolved-after-apply`) is reserved for `fix` and is never
// returned by `check`.
func decideExit(actionable, unresolved, failed int) error {
	switch {
	case failed > 0:
		return exitErr{code: 1, msg: fmt.Sprintf("%d workspace(s) failed", failed)}
	case actionable > 0 || unresolved > 0:
		return exitErr{code: 10}
	}
	return nil
}

// exitErr signals a specific exit code without writing a message
// (unless msg is set). The CLI runner unwraps this and exits with code.
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

// Code returns the desired exit code. Wired up in cli.Run by checking
// for exitErr (added in a later step if not yet wired).
func (e exitErr) Code() int { return e.code }

// JSON output types. Stable shape — additive changes only.

type jsonOutput struct {
	Root       string          `json:"root"`
	Workspaces []jsonWorkspace `json:"workspaces"`
	Summary    jsonSummary     `json:"summary"`
}

type jsonWorkspace struct {
	Name       string           `json:"name"`
	Dir        string           `json:"dir"`
	RelDir     string           `json:"relDir"`
	IsRoot     bool             `json:"isRoot"`
	Error      string           `json:"error,omitempty"`
	Actionable []jsonEdit       `json:"actionable"`
	Unresolved []jsonUnresolved `json:"unresolved"`
}

type jsonEdit struct {
	Kind            string `json:"kind"` // "bump-direct" | "bump-parent" | "override-add" | "exclude-from-cooldown"
	File            string `json:"file"`
	Package         string `json:"package"`
	Field           string `json:"field,omitempty"`
	From            string `json:"from,omitempty"`
	To              string `json:"to,omitempty"`
	VulnerableRange string `json:"vulnerableRange,omitempty"`
	Reason          string `json:"reason,omitempty"`
	RejectionNotes  string `json:"rejectionNotes,omitempty"`
}

type jsonUnresolved struct {
	GHSA     string `json:"ghsa"`
	Package  string `json:"package"`
	Severity string `json:"severity"`
	Reason   string `json:"reason"`
	Detail   string `json:"detail,omitempty"`
}

type jsonSummary struct {
	Workspaces int `json:"workspaces"`
	Actionable int `json:"actionable"`
	Unresolved int `json:"unresolved"`
	Failures   int `json:"failures"`
}

func writeJSON(w io.Writer, root string, results []WorkspaceResult) error {
	out := jsonOutput{
		Root:       root,
		Workspaces: make([]jsonWorkspace, 0, len(results)),
	}
	for _, r := range results {
		jw := jsonWorkspace{
			Name:       r.Workspace.Name,
			Dir:        r.Workspace.Dir,
			RelDir:     r.Workspace.RelDir,
			IsRoot:     r.Workspace.IsRoot,
			Actionable: []jsonEdit{},
			Unresolved: []jsonUnresolved{},
		}
		if r.Err != nil {
			jw.Error = r.Err.Error()
			out.Summary.Failures++
		} else {
			for _, e := range r.Plan.Actionable {
				jw.Actionable = append(jw.Actionable, jsonEdit{
					Kind:            string(e.Kind),
					File:            e.File,
					Package:         e.Package,
					Field:           e.Field,
					From:            e.From,
					To:              e.To,
					VulnerableRange: e.VulnerableRange,
					Reason:          e.Reason,
					RejectionNotes:  e.RejectionNotes,
				})
			}
			for _, u := range r.Plan.Unresolved {
				jw.Unresolved = append(jw.Unresolved, jsonUnresolved{
					GHSA:     u.Finding.Advisory.GHSA,
					Package:  u.Finding.Advisory.Package,
					Severity: string(u.Finding.Advisory.Severity),
					Reason:   u.Reason,
					Detail:   u.Detail,
				})
			}
			out.Summary.Actionable += len(jw.Actionable)
			out.Summary.Unresolved += len(jw.Unresolved)
		}
		out.Workspaces = append(out.Workspaces, jw)
	}
	out.Summary.Workspaces = len(results)

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(out)
}

// WorkspaceResult is the per-workspace pipeline result: audit ->
// triage -> plan. Err is non-nil if any stage failed for this
// workspace; on failure, Findings and Plan are zero values.
type WorkspaceResult struct {
	Workspace pkgmgr.Workspace
	Findings  []pkgmgr.Finding
	Plan      pkgmgr.Plan
	Err       error
}

// processAll runs the audit -> triage -> plan pipeline per workspace,
// concurrently, bounded by concurrency. All audits finish before any
// planning starts, so the planner sees every workspace's allowlisted
// findings. Order in the result matches the input order. The registry
// cache inside the planner is shared across goroutines (it's safe for
// concurrent use). Progress lines are written to progress as each
// workspace's audit completes; planning failures are reported after.
func processAll(
	pm pkgmgr.PkgManager,
	planner *plan.Builder,
	allowlist auditci.Allowlist,
	workspaces []pkgmgr.Workspace,
	concurrency int,
	progress io.Writer,
) []WorkspaceResult {
	if concurrency < 1 {
		concurrency = 1
	}
	results := make([]WorkspaceResult, len(workspaces))
	skipped := make([][]pkgmgr.Advisory, len(workspaces))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var (
		progressMu sync.Mutex
		done       int
		total      = len(workspaces)
	)

	report := func(ws pkgmgr.Workspace, skipped int, err error) {
		progressMu.Lock()
		defer progressMu.Unlock()
		done++
		label := workspaceLabel(ws)
		if err != nil {
			fmt.Fprintf(progress, "  x %s (%d/%d): %v\n", label, done, total, err)
		} else {
			fmt.Fprintf(progress, "  o %s (%d/%d)\n", label, done, total)
		}
		if skipped > 0 {
			fmt.Fprintf(progress, "    %d advisory finding(s) skipped (allowlisted)\n", skipped)
		}
	}

	// Phase 1: audit, filter, and triage every workspace. Planning waits
	// until all allowlisted findings are known, because overrides land at
	// the monorepo root and can rewrite allowlisted paths in any workspace.
	for i, ws := range workspaces {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, ws pkgmgr.Workspace) {
			defer wg.Done()
			defer func() { <-sem }()
			advs, err := pm.Audit(ws)
			if err != nil {
				results[i] = WorkspaceResult{Workspace: ws, Err: err}
				report(ws, 0, err)
				return
			}
			advs, skipped[i] = allowlist.Filter(advs)
			findings, err := triage.Run(advs)
			if err != nil {
				results[i] = WorkspaceResult{Workspace: ws, Err: err}
				report(ws, len(skipped[i]), err)
				return
			}
			results[i] = WorkspaceResult{Workspace: ws, Findings: findings}
			report(ws, len(skipped[i]), nil)
		}(i, ws)
	}
	wg.Wait()

	scoped := *planner
	scoped.Allowlisted = nil
	for _, s := range skipped {
		scoped.Allowlisted = append(scoped.Allowlisted, s...)
	}

	// Phase 2: plan each successfully triaged workspace.
	for i := range results {
		if results[i].Err != nil {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(r *WorkspaceResult) {
			defer wg.Done()
			defer func() { <-sem }()
			p, err := scoped.Build(r.Findings)
			if err != nil {
				r.Err = err
				progressMu.Lock()
				fmt.Fprintf(progress, "  x %s: plan: %v\n", workspaceLabel(r.Workspace), err)
				progressMu.Unlock()
				return
			}
			r.Plan = p
		}(&results[i])
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

func printResults(w io.Writer, results []WorkspaceResult) {
	for _, r := range results {
		header := workspaceHeader(r.Workspace)
		if r.Err != nil {
			fmt.Fprintf(w, "%s  [failed: %v]\n", header, r.Err)
			continue
		}
		actionable := r.Plan.Actionable
		unresolved := r.Plan.Unresolved
		if len(actionable) == 0 && len(unresolved) == 0 {
			fmt.Fprintf(w, "%s  no findings\n", header)
			continue
		}
		fmt.Fprintf(w, "%s  %d actionable, %d unresolved\n", header, len(actionable), len(unresolved))
		for _, e := range actionable {
			switch e.Kind {
			case pkgmgr.EditBumpDirect:
				fmt.Fprintf(w, "    bump-direct  %s  %s -> %s  (%s)  %s\n",
					e.Package, e.From, e.To, e.Field, e.Reason)
			case pkgmgr.EditBumpParent:
				fmt.Fprintf(w, "    bump-parent  %s  %s -> %s  (%s)  %s\n",
					e.Package, e.From, e.To, e.Field, e.Reason)
			case pkgmgr.EditOverrideAdd:
				fmt.Fprintf(w, "    override     %s@%s -> %s  %s\n",
					e.Package, e.VulnerableRange, e.To, e.Reason)
				if e.RejectionNotes != "" {
					fmt.Fprintf(w, "                 (%s)\n", e.RejectionNotes)
				}
			case pkgmgr.EditExcludeFromCooldown:
				fmt.Fprintf(w, "    cooldown-bypass  %s@%s  %s\n",
					e.Package, e.To, e.Reason)
			default:
				fmt.Fprintf(w, "    %s  %+v\n", e.Kind, e)
			}
		}
		for _, u := range unresolved {
			a := u.Finding.Advisory
			fmt.Fprintf(w, "    unresolved   %s  %s (%s)  reason=%s\n",
				a.Package, a.GHSA, a.Severity, u.Reason)
			if u.Detail != "" {
				fmt.Fprintf(w, "                 (%s)\n", u.Detail)
			}
		}
	}
}

func workspaceHeader(ws pkgmgr.Workspace) string {
	return "- " + workspaceLabel(ws)
}

// workspaceLabel returns a human-friendly identifier for a workspace,
// preferring the relative dir (which is grep-able and cd-able) over
// the package.json name (which may not reflect on-disk location).
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

func sortFindings(findings []pkgmgr.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Advisory.Package != findings[j].Advisory.Package {
			return findings[i].Advisory.Package < findings[j].Advisory.Package
		}
		return findings[i].Advisory.GHSA < findings[j].Advisory.GHSA
	})
}

// severity ordering
var severityRank = map[pkgmgr.Severity]int{
	pkgmgr.SeverityLow:      0,
	pkgmgr.SeverityModerate: 1,
	pkgmgr.SeverityHigh:     2,
	pkgmgr.SeverityCritical: 3,
}

func minSeverity(s string) int {
	if r, ok := severityRank[pkgmgr.Severity(s)]; ok {
		return r
	}
	return severityRank[pkgmgr.SeverityModerate]
}

// filterEditsBySeverity returns edits whose advisory severity meets min.
// findings is the source list of triaged findings (one per edit at most);
// edits are matched by package + file.
func filterEditsBySeverity(edits []pkgmgr.Edit, findings []pkgmgr.Finding, min int) []pkgmgr.Edit {
	sevByKey := map[string]pkgmgr.Severity{}
	for _, f := range findings {
		key := f.Advisory.Workspace.PackageJSON + "\x00" + f.Advisory.Package + "\x00" + f.Advisory.GHSA
		sevByKey[key] = f.Advisory.Severity
	}
	out := edits[:0:0]
	for _, e := range edits {
		// Conservative: keep if we can't match severity (don't filter
		// override edits whose finding details differ).
		if severityRank[mostRelevantSeverity(e, findings)] >= min {
			out = append(out, e)
		}
	}
	return out
}

// mostRelevantSeverity finds the highest-severity finding associated
// with an edit. Bump edits are scoped to a specific workspace's
// package.json so we match by file. Override edits live at the
// monorepo root and apply globally — match any finding on that vuln
// package across the run. Falls back to Critical so the edit isn't
// filtered out by accident.
func mostRelevantSeverity(e pkgmgr.Edit, findings []pkgmgr.Finding) pkgmgr.Severity {
	highest := pkgmgr.SeverityLow
	matched := false
	for _, f := range findings {
		switch e.Kind {
		case pkgmgr.EditOverrideAdd, pkgmgr.EditOverrideConsolidate, pkgmgr.EditExcludeFromCooldown:
			// Override / cooldown-exclude are root-scoped; ignore the
			// workspace and match by vuln package.
			if f.Advisory.Package != e.Package {
				continue
			}
		case pkgmgr.EditBumpParent:
			if f.Advisory.Workspace.PackageJSON != e.File || f.Parent != e.Package {
				continue
			}
		default:
			if f.Advisory.Workspace.PackageJSON != e.File || f.Advisory.Package != e.Package {
				continue
			}
		}
		if severityRank[f.Advisory.Severity] >= severityRank[highest] {
			highest = f.Advisory.Severity
			matched = true
		}
	}
	if !matched {
		return pkgmgr.SeverityCritical
	}
	return highest
}

// filterResultsBySeverity returns a copy of results with each Plan's
// Actionable/Unresolved narrowed to entries meeting min severity.
// Failed workspaces (Err != nil) are passed through unchanged so they
// still count toward the failure exit code.
func filterResultsBySeverity(results []WorkspaceResult, min int) []WorkspaceResult {
	out := make([]WorkspaceResult, len(results))
	for i, r := range results {
		out[i] = r
		if r.Err != nil {
			continue
		}
		out[i].Plan.Actionable = filterEditsBySeverity(r.Plan.Actionable, r.Findings, min)
		out[i].Plan.Unresolved = filterUnresolvedBySeverity(r.Plan.Unresolved, min)
	}
	return out
}

func filterUnresolvedBySeverity(items []pkgmgr.Unresolved, min int) []pkgmgr.Unresolved {
	out := items[:0:0]
	for _, u := range items {
		if severityRank[u.Finding.Advisory.Severity] >= min {
			out = append(out, u)
		}
	}
	return out
}

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
