package checkcmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"sort"
	"sync"

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
}

func Run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)

	opts := Options{}
	fs.StringVar(&opts.Dir, "dir", ".", "monorepo root (directory containing pnpm-workspace.yaml)")
	fs.StringVar(&opts.Severity, "severity", "moderate", "minimum severity to report (low|moderate|high|critical)")
	fs.BoolVar(&opts.JSON, "json", false, "emit machine-readable JSON to stdout")
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
	fmt.Fprintf(stderr, "auditing %d workspace(s) (concurrency=%d)...\n",
		len(workspaces), opts.Concurrency)

	reg := registry.New()
	planner := plan.New(reg)
	results := processAll(pm, planner, workspaces, opts.Concurrency, stderr)

	rootDir := opts.Dir
	for _, ws := range workspaces {
		if ws.IsRoot {
			rootDir = ws.Dir
			break
		}
	}

	totalActionable, totalUnresolved, failedCount := summarize(results)
	fmt.Fprintf(stderr,
		"checked %d workspace(s) under %s: %d actionable, %d unresolved, %d failure(s)\n",
		len(results), rootDir, totalActionable, totalUnresolved, failedCount)

	if opts.JSON {
		if err := writeJSON(stdout, rootDir, results, minSeverity(opts.Severity)); err != nil {
			return err
		}
	} else {
		printResults(stdout, results, minSeverity(opts.Severity))
	}

	// Exit code precedence: tool error > unresolved > actionable > clean.
	switch {
	case failedCount > 0:
		return exitErr{code: 1, msg: fmt.Sprintf("%d workspace(s) failed", failedCount)}
	case totalUnresolved > 0:
		return exitErr{code: 20}
	case totalActionable > 0:
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
	Kind            string `json:"kind"` // "bump-direct" | "bump-parent" | "override-add"
	File            string `json:"file"`
	Package         string `json:"package"`
	Field           string `json:"field,omitempty"`
	From            string `json:"from,omitempty"`
	To              string `json:"to,omitempty"`
	VulnerableRange string `json:"vulnerableRange,omitempty"`
	Reason          string `json:"reason,omitempty"`
}

type jsonUnresolved struct {
	GHSA     string `json:"ghsa"`
	Package  string `json:"package"`
	Severity string `json:"severity"`
	Reason   string `json:"reason"`
}

type jsonSummary struct {
	Workspaces int `json:"workspaces"`
	Actionable int `json:"actionable"`
	Unresolved int `json:"unresolved"`
	Failures   int `json:"failures"`
}

func writeJSON(w io.Writer, root string, results []WorkspaceResult, minSev int) error {
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
			actionable := filterEditsBySeverity(r.Plan.Actionable, r.Findings, minSev)
			unresolved := filterUnresolvedBySeverity(r.Plan.Unresolved, minSev)
			for _, e := range actionable {
				jw.Actionable = append(jw.Actionable, jsonEdit{
					Kind:            string(e.Kind),
					File:            e.File,
					Package:         e.Package,
					Field:           e.Field,
					From:            e.From,
					To:              e.To,
					VulnerableRange: e.VulnerableRange,
					Reason:          e.Reason,
				})
			}
			for _, u := range unresolved {
				jw.Unresolved = append(jw.Unresolved, jsonUnresolved{
					GHSA:     u.Finding.Advisory.GHSA,
					Package:  u.Finding.Advisory.Package,
					Severity: string(u.Finding.Advisory.Severity),
					Reason:   u.Reason,
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
// concurrently, bounded by concurrency. Order in the result matches
// the input order. The registry cache inside the planner is shared
// across goroutines (it's safe for concurrent use). Progress lines
// are written to progress as each workspace completes.
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

func printResults(w io.Writer, results []WorkspaceResult, minSev int) {
	for _, r := range results {
		header := workspaceHeader(r.Workspace)
		if r.Err != nil {
			fmt.Fprintf(w, "%s  [failed: %v]\n", header, r.Err)
			continue
		}
		actionable := filterEditsBySeverity(r.Plan.Actionable, r.Findings, minSev)
		unresolved := filterUnresolvedBySeverity(r.Plan.Unresolved, minSev)
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
			default:
				fmt.Fprintf(w, "    %s  %+v\n", e.Kind, e)
			}
		}
		for _, u := range unresolved {
			a := u.Finding.Advisory
			fmt.Fprintf(w, "    unresolved   %s  %s (%s)  reason=%s\n",
				a.Package, a.GHSA, a.Severity, u.Reason)
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
// with an edit (matched by Package + File). Falls back to Critical so
// the edit isn't filtered out by accident.
func mostRelevantSeverity(e pkgmgr.Edit, findings []pkgmgr.Finding) pkgmgr.Severity {
	highest := pkgmgr.SeverityLow
	matched := false
	for _, f := range findings {
		if f.Advisory.Workspace.PackageJSON != e.File {
			continue
		}
		// For bump-direct, edit.Package == advisory.Package.
		// For bump-parent, edit.Package is the parent; we match by parent.
		// For override-add, edit.Package == advisory.Package.
		if e.Kind == pkgmgr.EditBumpParent {
			if f.Parent != e.Package {
				continue
			}
		} else if f.Advisory.Package != e.Package {
			continue
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

func filterUnresolvedBySeverity(items []pkgmgr.Unresolved, min int) []pkgmgr.Unresolved {
	out := items[:0:0]
	for _, u := range items {
		if severityRank[u.Finding.Advisory.Severity] >= min {
			out = append(out, u)
		}
	}
	return out
}
