package checkcmd

import (
	"testing"

	"github.com/robertkasza/deps/internal/pkgmgr"
)

// Exit-code contract for `deps check`:
//   0  clean
//   1  tool error (workspace failures)
//  10  actionable or unresolved findings present
//  20  reserved for `deps fix` (`unresolved-after-apply`); never returned here
func TestDecideExit(t *testing.T) {
	cases := []struct {
		name                  string
		actionable, unresolved, failed int
		wantNil               bool
		wantCode              int
	}{
		{"clean", 0, 0, 0, true, 0},
		{"actionable only", 3, 0, 0, false, 10},
		{"unresolved only", 0, 2, 0, false, 10},
		{"both present", 1, 1, 0, false, 10},
		{"failure trumps findings", 5, 5, 1, false, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := decideExit(tc.actionable, tc.unresolved, tc.failed)
			if tc.wantNil {
				if err != nil {
					t.Fatalf("want nil, got %v", err)
				}
				return
			}
			ee, ok := err.(exitErr)
			if !ok {
				t.Fatalf("want exitErr, got %T (%v)", err, err)
			}
			if ee.Code() != tc.wantCode {
				t.Fatalf("want code %d, got %d", tc.wantCode, ee.Code())
			}
			if tc.wantCode == 20 {
				t.Fatalf("check must never return code 20; that is reserved for fix")
			}
		})
	}
}

// `--severity` filters display, JSON, summary and exit code together.
// Regression: previously summarize ran on the unfiltered plan, so
// `deps check --severity critical` could exit 10 while showing zero
// findings. The fix routes everything through filterResultsBySeverity
// before summarize.
func TestSeverityFilterDrivesExitCode(t *testing.T) {
	ws := pkgmgr.Workspace{
		Dir:         "/repo/apps/admin",
		RelDir:      "apps/admin",
		PackageJSON: "/repo/apps/admin/package.json",
		Name:        "admin",
	}
	moderate := pkgmgr.Advisory{
		GHSA:      "GHSA-moderate",
		Severity:  pkgmgr.SeverityModerate,
		Package:   "lodash",
		Workspace: ws,
	}
	finding := pkgmgr.Finding{Advisory: moderate, Kind: pkgmgr.FindingDirect}
	results := []WorkspaceResult{{
		Workspace: ws,
		Findings:  []pkgmgr.Finding{finding},
		Plan: pkgmgr.Plan{
			Actionable: []pkgmgr.Edit{{
				Kind:    pkgmgr.EditBumpDirect,
				File:    ws.PackageJSON,
				Package: "lodash",
				Field:   "dependencies",
				From:    "^4.17.20",
				To:      "^4.17.21",
			}},
			Unresolved: []pkgmgr.Unresolved{{Finding: finding, Reason: "no-fix"}},
		},
	}}

	// Sanity: at moderate threshold, both rows survive and check exits 10.
	atModerate := filterResultsBySeverity(results, minSeverity("moderate"))
	a, u, f := summarize(atModerate)
	if a != 1 || u != 1 || f != 0 {
		t.Fatalf("moderate threshold: want 1/1/0, got %d/%d/%d", a, u, f)
	}
	if err := decideExit(a, u, f); err == nil || err.(exitErr).Code() != 10 {
		t.Fatalf("moderate threshold: want exit 10, got %v", err)
	}

	// Bug repro: at critical threshold, no rows survive, so summary
	// must read 0/0/0 and exit must be 0 (not 10).
	atCritical := filterResultsBySeverity(results, minSeverity("critical"))
	a, u, f = summarize(atCritical)
	if a != 0 || u != 0 || f != 0 {
		t.Fatalf("critical threshold: want 0/0/0, got %d/%d/%d", a, u, f)
	}
	if err := decideExit(a, u, f); err != nil {
		t.Fatalf("critical threshold: want nil exit, got %v", err)
	}
}
