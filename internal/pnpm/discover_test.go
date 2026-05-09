package pnpm

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// fixture builds a temporary directory tree for a discovery test.
// Each entry maps a relative path to file contents; intermediate
// directories are created automatically. A path ending in "/" creates
// an empty directory.
type fixture map[string]string

func (f fixture) build(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for rel, contents := range f {
		full := filepath.Join(root, rel)
		if rel[len(rel)-1] == '/' {
			if err := os.MkdirAll(full, 0o755); err != nil {
				t.Fatalf("mkdir %s: %v", full, err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir parent of %s: %v", full, err)
		}
		if err := os.WriteFile(full, []byte(contents), 0o644); err != nil {
			t.Fatalf("write %s: %v", full, err)
		}
	}
	return root
}

func TestDiscoverWorkspaces(t *testing.T) {
	tests := []struct {
		name      string
		fixture   fixture
		wantNames []string // workspace.Name values, sorted
		wantErr   bool
	}{
		{
			name: "single package repo (no pnpm-workspace.yaml)",
			fixture: fixture{
				"package.json": `{"name": "solo"}`,
			},
			wantNames: []string{"solo"},
		},
		{
			name: "simple monorepo with apps and packages",
			fixture: fixture{
				"package.json":         `{"name": "root"}`,
				"pnpm-workspace.yaml":  "packages:\n  - apps/*\n  - packages/*\n",
				"apps/web/package.json":     `{"name": "web"}`,
				"apps/admin/package.json":   `{"name": "admin"}`,
				"packages/ui/package.json":  `{"name": "ui"}`,
			},
			wantNames: []string{"admin", "root", "ui", "web"},
		},
		{
			name: "doublestar glob",
			fixture: fixture{
				"package.json":        `{"name": "root"}`,
				"pnpm-workspace.yaml": "packages:\n  - packages/**\n",
				"packages/a/package.json":     `{"name": "a"}`,
				"packages/b/c/package.json":   `{"name": "c"}`,
			},
			wantNames: []string{"a", "c", "root"},
		},
		{
			name: "negation excludes a workspace",
			fixture: fixture{
				"package.json":        `{"name": "root"}`,
				"pnpm-workspace.yaml": "packages:\n  - packages/*\n  - '!packages/internal'\n",
				"packages/public/package.json":   `{"name": "public"}`,
				"packages/internal/package.json": `{"name": "internal"}`,
			},
			wantNames: []string{"public", "root"},
		},
		{
			name: "directory matches glob but has no package.json is skipped",
			fixture: fixture{
				"package.json":        `{"name": "root"}`,
				"pnpm-workspace.yaml": "packages:\n  - packages/*\n",
				"packages/real/package.json": `{"name": "real"}`,
				"packages/empty/":            "",
			},
			wantNames: []string{"real", "root"},
		},
		{
			name: "node_modules paths are ignored even when matched",
			fixture: fixture{
				"package.json":        `{"name": "root"}`,
				"pnpm-workspace.yaml": "packages:\n  - '**'\n",
				"node_modules/lodash/package.json":     `{"name": "lodash"}`,
				"packages/ui/node_modules/x/package.json": `{"name": "x"}`,
				"packages/ui/package.json":             `{"name": "ui"}`,
			},
			wantNames: []string{"root", "ui"},
		},
		{
			name: "unnamed package is included with empty name",
			fixture: fixture{
				"package.json":        `{"name": "root"}`,
				"pnpm-workspace.yaml": "packages:\n  - apps/*\n",
				"apps/anon/package.json": `{}`,
			},
			wantNames: []string{"", "root"},
		},
		{
			name: "missing root package.json is an error",
			fixture: fixture{
				"pnpm-workspace.yaml": "packages:\n  - apps/*\n",
			},
			wantErr: true,
		},
	}

	a := New()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := tc.fixture.build(t)
			got, err := a.DiscoverWorkspaces(root)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			var names []string
			for _, ws := range got {
				names = append(names, ws.Name)
			}
			sort.Strings(names)
			if !equalSlices(names, tc.wantNames) {
				t.Errorf("names: got %v, want %v", names, tc.wantNames)
			}
		})
	}
}

func TestDiscoverWorkspaces_RootMarker(t *testing.T) {
	root := fixture{
		"package.json":              `{"name": "root"}`,
		"pnpm-workspace.yaml":       "packages:\n  - apps/*\n",
		"apps/web/package.json":     `{"name": "web"}`,
	}.build(t)

	got, err := New().DiscoverWorkspaces(root)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}

	var rootCount int
	for _, ws := range got {
		if ws.IsRoot {
			rootCount++
			if ws.Name != "root" {
				t.Errorf("root workspace name: got %q, want %q", ws.Name, "root")
			}
		}
	}
	if rootCount != 1 {
		t.Errorf("expected exactly one root workspace, got %d", rootCount)
	}
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
