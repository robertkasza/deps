package pnpm

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/robertkasza/deps/internal/pkgmgr"
)

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return data
}

func TestParseAudit_VulnTestFixture(t *testing.T) {
	data := loadFixture(t, "audit_vuln-test.json")

	tests := []struct {
		name           string
		ws             pkgmgr.Workspace
		wantPackages   []string // sorted, deduplicated module names attributed to this ws
		wantAtLeast    int
	}{
		{
			name: "apps/admin gets request (direct) plus form-data, qs, tough-cookie (transitive)",
			ws: pkgmgr.Workspace{
				Name:   "@vuln-test/admin",
				RelDir: "apps/admin",
			},
			wantPackages: []string{"form-data", "qs", "request", "tough-cookie"},
			wantAtLeast:  4,
		},
		{
			name: "packages/utils gets body-parser (direct) and qs (transitive)",
			ws: pkgmgr.Workspace{
				Name:   "@vuln-test/utils",
				RelDir: "packages/utils",
			},
			wantPackages: []string{"body-parser", "qs"},
			wantAtLeast:  2,
		},
		{
			name: "apps/web gets minimist (direct devDependency)",
			ws: pkgmgr.Workspace{
				Name:   "@vuln-test/web",
				RelDir: "apps/web",
			},
			wantPackages: []string{"minimist"},
			wantAtLeast:  1,
		},
		{
			name: "root workspace gets its own direct dep (lodash)",
			ws: pkgmgr.Workspace{
				Name:   "vuln-test",
				IsRoot: true,
			},
			wantPackages: []string{"lodash"},
			wantAtLeast:  1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			advs, err := parseAudit(data, tc.ws)
			if err != nil {
				t.Fatalf("parseAudit: %v", err)
			}
			if len(advs) < tc.wantAtLeast {
				t.Errorf("count: got %d, want >= %d", len(advs), tc.wantAtLeast)
			}
			gotPackages := uniqueSorted(advs, func(a pkgmgr.Advisory) string { return a.Package })
			if !equalSlices(gotPackages, tc.wantPackages) {
				t.Errorf("packages: got %v, want %v", gotPackages, tc.wantPackages)
			}

			// Every advisory should be attributed to the requested workspace.
			for _, a := range advs {
				if a.Workspace.RelDir != tc.ws.RelDir || a.Workspace.IsRoot != tc.ws.IsRoot {
					t.Errorf("advisory attributed to wrong workspace: got %+v, want %+v",
						a.Workspace, tc.ws)
				}
				if a.GHSA == "" {
					t.Errorf("advisory %s missing GHSA id", a.Package)
				}
				if len(a.Path) == 0 {
					t.Errorf("advisory %s has empty path", a.Package)
				}
			}
		})
	}
}

func TestParseAudit_Errors(t *testing.T) {
	ws := pkgmgr.Workspace{IsRoot: true}

	if _, err := parseAudit(nil, ws); err == nil {
		t.Errorf("expected error on empty input")
	}
	if _, err := parseAudit([]byte("not json"), ws); err == nil {
		t.Errorf("expected error on malformed JSON")
	}
	// Empty advisories map is valid (no vulns).
	advs, err := parseAudit([]byte(`{"advisories":{}}`), ws)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(advs) != 0 {
		t.Errorf("expected 0 advisories, got %d", len(advs))
	}
}

func TestMatchPath(t *testing.T) {
	tests := []struct {
		path     string
		prefix   string
		isRoot   bool
		want     []string
		wantOk   bool
	}{
		{"apps__admin>request", "apps__admin", false, []string{"request"}, true},
		{"apps__admin>request>tough-cookie", "apps__admin", false, []string{"request", "tough-cookie"}, true},
		{"apps__admin>request", "packages__utils", false, nil, false},
		{".>lodash", "", true, []string{"lodash"}, true},
		{".>request>tough-cookie", "", true, []string{"request", "tough-cookie"}, true},
		{"apps__admin>request", "", true, nil, false}, // workspace path, not root
		{"lodash", "", true, nil, false},              // single segment can't originate anywhere
		{"", "apps__admin", false, nil, false},
	}
	for _, tc := range tests {
		got, ok := matchPath(tc.path, tc.prefix, tc.isRoot)
		if ok != tc.wantOk {
			t.Errorf("matchPath(%q,%q,root=%v) ok: got %v, want %v",
				tc.path, tc.prefix, tc.isRoot, ok, tc.wantOk)
		}
		if !equalSlices(got, tc.want) {
			t.Errorf("matchPath(%q,%q,root=%v) chain: got %v, want %v",
				tc.path, tc.prefix, tc.isRoot, got, tc.want)
		}
	}
}

func uniqueSorted(advs []pkgmgr.Advisory, key func(pkgmgr.Advisory) string) []string {
	seen := map[string]struct{}{}
	for _, a := range advs {
		seen[key(a)] = struct{}{}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
