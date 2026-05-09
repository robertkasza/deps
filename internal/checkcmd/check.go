package checkcmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"runtime"
	"sort"
	"sync"

	"github.com/robertkasza/deps/internal/pkgmgr"
	"github.com/robertkasza/deps/internal/pnpm"
	"github.com/robertkasza/deps/internal/triage"
)

type Options struct {
	Dir      string
	Severity string
	JSON     bool
}

func Run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)

	opts := Options{}
	fs.StringVar(&opts.Dir, "dir", ".", "monorepo root (directory containing pnpm-workspace.yaml)")
	fs.StringVar(&opts.Severity, "severity", "moderate", "minimum severity to report (low|moderate|high|critical)")
	fs.BoolVar(&opts.JSON, "json", false, "emit machine-readable JSON to stdout")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}

	pm := pnpm.New()
	workspaces, err := pm.DiscoverWorkspaces(opts.Dir)
	if err != nil {
		return fmt.Errorf("discover workspaces: %w", err)
	}

	results := auditAll(pm, workspaces, runtime.NumCPU())

	rootDir := opts.Dir
	for _, ws := range workspaces {
		if ws.IsRoot {
			rootDir = ws.Dir
			break
		}
	}

	totalFindings, failedCount := summarize(results)
	fmt.Fprintf(stderr, "checked %d workspace(s) under %s: %d finding(s), %d failure(s)\n",
		len(results), rootDir, totalFindings, failedCount)

	if opts.JSON {
		if err := writeJSON(stdout, rootDir, results, minSeverity(opts.Severity)); err != nil {
			return err
		}
	} else {
		printResults(stdout, results, minSeverity(opts.Severity))
	}

	if failedCount > 0 {
		return fmt.Errorf("%d workspace(s) failed to audit", failedCount)
	}
	return nil
}

// JSON output types. Stable shape — additive changes only.

type jsonOutput struct {
	Root       string          `json:"root"`
	Workspaces []jsonWorkspace `json:"workspaces"`
	Summary    jsonSummary     `json:"summary"`
}

type jsonWorkspace struct {
	Name     string        `json:"name"`
	Dir      string        `json:"dir"`
	RelDir   string        `json:"relDir"`
	IsRoot   bool          `json:"isRoot"`
	Error    string        `json:"error,omitempty"`
	Findings []jsonFinding `json:"findings"`
}

type jsonFinding struct {
	GHSA            string   `json:"ghsa"`
	Severity        string   `json:"severity"`
	Package         string   `json:"package"`
	Kind            string   `json:"kind"`             // "direct" | "transitive"
	Parent          string   `json:"parent,omitempty"` // set when kind == transitive
	VulnerableRange string   `json:"vulnerableRange"`
	FixedRange      string   `json:"fixedRange"`
	Path            []string `json:"path"`
	URL             string   `json:"url,omitempty"`
}

type jsonSummary struct {
	Workspaces int `json:"workspaces"`
	Findings   int `json:"findings"`
	Failures   int `json:"failures"`
}

func writeJSON(w io.Writer, root string, results []WorkspaceAudit, minSev int) error {
	out := jsonOutput{
		Root:       root,
		Workspaces: make([]jsonWorkspace, 0, len(results)),
	}
	for _, r := range results {
		jw := jsonWorkspace{
			Name:     r.Workspace.Name,
			Dir:      r.Workspace.Dir,
			RelDir:   r.Workspace.RelDir,
			IsRoot:   r.Workspace.IsRoot,
			Findings: []jsonFinding{},
		}
		if r.Err != nil {
			jw.Error = r.Err.Error()
			out.Summary.Failures++
		} else {
			filtered := filterBySeverity(r.Findings, minSev)
			sortFindings(filtered)
			for _, f := range filtered {
				a := f.Advisory
				jw.Findings = append(jw.Findings, jsonFinding{
					GHSA:            a.GHSA,
					Severity:        string(a.Severity),
					Package:         a.Package,
					Kind:            string(f.Kind),
					Parent:          f.Parent,
					VulnerableRange: a.VulnerableRange,
					FixedRange:      a.FixedRange,
					Path:            a.Path,
					URL:             a.URL,
				})
			}
			out.Summary.Findings += len(jw.Findings)
		}
		out.Workspaces = append(out.Workspaces, jw)
	}
	out.Summary.Workspaces = len(results)

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(out)
}

// WorkspaceAudit is the per-workspace result of audit + triage. If
// audit succeeds, Findings holds one entry per advisory finding
// (already classified direct/transitive). Err is non-nil if either
// audit or triage failed for this workspace.
type WorkspaceAudit struct {
	Workspace pkgmgr.Workspace
	Findings  []pkgmgr.Finding
	Err       error
}

// auditAll runs Audit on every workspace concurrently, bounded by
// concurrency. Order in the result matches the input order.
func auditAll(pm pkgmgr.PkgManager, workspaces []pkgmgr.Workspace, concurrency int) []WorkspaceAudit {
	if concurrency < 1 {
		concurrency = 1
	}
	results := make([]WorkspaceAudit, len(workspaces))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i, ws := range workspaces {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, ws pkgmgr.Workspace) {
			defer wg.Done()
			defer func() { <-sem }()
			advs, err := pm.Audit(ws)
			if err != nil {
				results[i] = WorkspaceAudit{Workspace: ws, Err: err}
				return
			}
			findings, err := triage.Run(advs)
			if err != nil {
				results[i] = WorkspaceAudit{Workspace: ws, Err: err}
				return
			}
			results[i] = WorkspaceAudit{Workspace: ws, Findings: findings}
		}(i, ws)
	}
	wg.Wait()
	return results
}

func summarize(results []WorkspaceAudit) (totalFindings, failed int) {
	for _, r := range results {
		if r.Err != nil {
			failed++
			continue
		}
		totalFindings += len(r.Findings)
	}
	return
}

func printResults(w io.Writer, results []WorkspaceAudit, minSev int) {
	for _, r := range results {
		header := workspaceHeader(r.Workspace)
		if r.Err != nil {
			fmt.Fprintf(w, "%s  [failed: %v]\n", header, r.Err)
			continue
		}
		filtered := filterBySeverity(r.Findings, minSev)
		if len(filtered) == 0 {
			fmt.Fprintf(w, "%s  no advisories\n", header)
			continue
		}
		sortFindings(filtered)
		fmt.Fprintf(w, "%s  %d finding(s)\n", header, len(filtered))
		for _, f := range filtered {
			a := f.Advisory
			classifier := string(f.Kind)
			if f.Kind == pkgmgr.FindingTransitive {
				classifier = fmt.Sprintf("transitive via %s", f.Parent)
			}
			fmt.Fprintf(w, "    [%s] [%s] %s  vulnerable=%s  fixed=%s  path=%v  %s\n",
				a.Severity, classifier, a.Package, a.VulnerableRange, a.FixedRange, a.Path, a.GHSA)
		}
	}
}

func workspaceHeader(ws pkgmgr.Workspace) string {
	tag := ""
	if ws.IsRoot {
		tag = " (root)"
	}
	name := ws.Name
	if name == "" {
		name = "<unnamed>"
	}
	return fmt.Sprintf("- %s%s", name, tag)
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

func filterBySeverity(findings []pkgmgr.Finding, min int) []pkgmgr.Finding {
	out := findings[:0:0]
	for _, f := range findings {
		if severityRank[f.Advisory.Severity] >= min {
			out = append(out, f)
		}
	}
	return out
}
