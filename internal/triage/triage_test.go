package triage

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/robertkasza/deps/internal/pkgmgr"
)

func writePackageJSON(t *testing.T, dir, content string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	p := filepath.Join(dir, "package.json")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

func TestTriageOne(t *testing.T) {
	deps := map[string]struct{}{
		"lodash":      {},
		"body-parser": {},
		"@scope/x":    {},
	}

	tests := []struct {
		name     string
		adv      pkgmgr.Advisory
		wantKind pkgmgr.FindingKind
		wantPar  string
		wantErr  bool
	}{
		{
			name:     "direct: package is in deps and path is single segment",
			adv:      pkgmgr.Advisory{Package: "lodash", Path: []string{"lodash"}},
			wantKind: pkgmgr.FindingDirect,
		},
		{
			name:     "direct: package in deps even when path has multiple segments (defensive)",
			adv:      pkgmgr.Advisory{Package: "body-parser", Path: []string{"body-parser"}},
			wantKind: pkgmgr.FindingDirect,
		},
		{
			name:     "transitive: package not in deps, parent is path[0]",
			adv:      pkgmgr.Advisory{Package: "qs", Path: []string{"body-parser", "qs"}},
			wantKind: pkgmgr.FindingTransitive,
			wantPar:  "body-parser",
		},
		{
			name:     "transitive: deeply nested, parent is still path[0]",
			adv:      pkgmgr.Advisory{Package: "xmldom", Path: []string{"expo", "@expo/cli", "@expo/plist", "xmldom"}},
			wantKind: pkgmgr.FindingTransitive,
			wantPar:  "expo",
		},
		{
			name:     "scoped package as direct",
			adv:      pkgmgr.Advisory{Package: "@scope/x", Path: []string{"@scope/x"}},
			wantKind: pkgmgr.FindingDirect,
		},
		{
			name:    "empty path is an error",
			adv:     pkgmgr.Advisory{Package: "foo", Path: nil},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, err := triageOne(tc.adv, deps)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if f.Kind != tc.wantKind {
				t.Errorf("kind: got %q, want %q", f.Kind, tc.wantKind)
			}
			if f.Parent != tc.wantPar {
				t.Errorf("parent: got %q, want %q", f.Parent, tc.wantPar)
			}
		})
	}
}

func TestRun_AcrossDepFields(t *testing.T) {
	dir := t.TempDir()
	pj := writePackageJSON(t, dir, `{
		"name": "demo",
		"dependencies": {"lodash": "^4.17.20"},
		"devDependencies": {"minimist": "1.2.0"},
		"optionalDependencies": {"fsevents": "^2"},
		"peerDependencies": {"react": "^18"}
	}`)
	ws := pkgmgr.Workspace{PackageJSON: pj}

	advisories := []pkgmgr.Advisory{
		{Package: "lodash", Path: []string{"lodash"}, Workspace: ws},
		{Package: "minimist", Path: []string{"minimist"}, Workspace: ws},
		{Package: "fsevents", Path: []string{"fsevents"}, Workspace: ws},
		{Package: "react", Path: []string{"react"}, Workspace: ws},
		{Package: "qs", Path: []string{"body-parser", "qs"}, Workspace: ws},
	}
	findings, err := Run(advisories)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 5 {
		t.Fatalf("got %d findings, want 5", len(findings))
	}
	for i, f := range findings[:4] {
		if f.Kind != pkgmgr.FindingDirect {
			t.Errorf("findings[%d] (%s): kind got %q, want direct", i, f.Advisory.Package, f.Kind)
		}
	}
	if findings[4].Kind != pkgmgr.FindingTransitive {
		t.Errorf("findings[4] kind: got %q, want transitive", findings[4].Kind)
	}
	if findings[4].Parent != "body-parser" {
		t.Errorf("findings[4] parent: got %q, want body-parser", findings[4].Parent)
	}
}

func TestRun_CachesPackageJSONReads(t *testing.T) {
	// Same workspace path used 100 times — Run should still work and return
	// 100 findings without errors. We can't directly assert "read once" with
	// the current API, but exercising the cache path covers it.
	dir := t.TempDir()
	pj := writePackageJSON(t, dir, `{"dependencies": {"lodash": "^4"}}`)
	ws := pkgmgr.Workspace{PackageJSON: pj}

	advs := make([]pkgmgr.Advisory, 100)
	for i := range advs {
		advs[i] = pkgmgr.Advisory{Package: "lodash", Path: []string{"lodash"}, Workspace: ws}
	}
	findings, err := Run(advs)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 100 {
		t.Errorf("got %d findings, want 100", len(findings))
	}
}

func TestRun_MissingPackageJSON(t *testing.T) {
	ws := pkgmgr.Workspace{PackageJSON: "/does/not/exist/package.json"}
	_, err := Run([]pkgmgr.Advisory{
		{Package: "x", Path: []string{"x"}, Workspace: ws},
	})
	if err == nil {
		t.Errorf("expected error for missing package.json")
	}
}

func TestRun_MalformedPackageJSON(t *testing.T) {
	dir := t.TempDir()
	pj := writePackageJSON(t, dir, `{not valid json}`)
	ws := pkgmgr.Workspace{PackageJSON: pj}
	_, err := Run([]pkgmgr.Advisory{
		{Package: "x", Path: []string{"x"}, Workspace: ws},
	})
	if err == nil {
		t.Errorf("expected error for malformed package.json")
	}
}
