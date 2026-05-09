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

func TestParseAudit_NhostDocsFixture_PerWorkspaceMode(t *testing.T) {
	// nhost emits per-workspace mode: paths start with ".". The fixture
	// is captured from `pnpm audit --json` inside docs/ which has two
	// fast-uri advisories reachable via @astrojs/vercel.
	data := loadFixture(t, "audit_nhost-docs.json")
	ws := pkgmgr.Workspace{
		Name:   "docs",
		RelDir: "docs",
	}
	advs, err := parseAudit(data, ws)
	if err != nil {
		t.Fatalf("parseAudit: %v", err)
	}
	if len(advs) == 0 {
		t.Errorf("expected fast-uri advisories, got none")
	}
	for _, a := range advs {
		if a.Package != "fast-uri" {
			t.Errorf("unexpected package %q", a.Package)
		}
		if len(a.Path) == 0 {
			t.Errorf("empty path for %s", a.GHSA)
		}
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
		name       string
		path       string
		prefix     string
		isRoot     bool
		globalMode bool
		want       []string
		wantOk     bool
	}{
		// Global mode (vuln-test fixture style).
		{"global: workspace finding via prefix", "apps__admin>request", "apps__admin", false, true, []string{"request"}, true},
		{"global: deep transitive", "apps__admin>request>tough-cookie", "apps__admin", false, true, []string{"request", "tough-cookie"}, true},
		{"global: other workspace's finding rejected", "apps__admin>request", "packages__utils", false, true, nil, false},
		{"global: root finding via dot", ".>lodash", "", true, true, []string{"lodash"}, true},
		{"global: root rejects workspace prefix", "apps__admin>request", "", true, true, nil, false},
		{"global: dot path NOT for non-root ws", ".>lodash", "apps__web", false, true, nil, false},

		// Per-workspace mode (nhost style).
		{"per-ws: dot path for current ws", ".>fast-uri", "docs", false, false, []string{"fast-uri"}, true},
		{"per-ws: deep transitive", ".>ajv>fast-uri", "docs", false, false, []string{"ajv", "fast-uri"}, true},
		{"per-ws: dot path for root", ".>lodash", "", true, false, []string{"lodash"}, true},
		{"per-ws: rejects __ prefix", "apps__admin>request", "apps__admin", false, false, nil, false},

		// Edge cases.
		{"empty path", "", "apps__admin", false, true, nil, false},
		{"single segment", "lodash", "", true, true, nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := matchPath(tc.path, tc.prefix, tc.isRoot, tc.globalMode)
			if ok != tc.wantOk {
				t.Errorf("ok: got %v, want %v", ok, tc.wantOk)
			}
			if !equalSlices(got, tc.want) {
				t.Errorf("chain: got %v, want %v", got, tc.want)
			}
		})
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
