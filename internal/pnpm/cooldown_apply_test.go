package pnpm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteCooldownExclude_FreshFile(t *testing.T) {
	root := t.TempDir()
	path, err := writeCooldownExclude(root, "turbo", "2.9.14")
	if err != nil {
		t.Fatalf("writeCooldownExclude: %v", err)
	}
	if path != filepath.Join(root, "pnpm-workspace.yaml") {
		t.Errorf("unexpected path %q", path)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !strings.Contains(string(got), "minimumReleaseAgeExclude:") {
		t.Errorf("missing minimumReleaseAgeExclude key:\n%s", got)
	}
	if !strings.Contains(string(got), `"turbo@2.9.14"`) {
		t.Errorf("missing entry turbo@2.9.14:\n%s", got)
	}
}

func TestWriteCooldownExclude_ExistingWorkspaceNoList(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "pnpm-workspace.yaml", `packages:
  - "apps/*"
  - "packages/*"
minimumReleaseAge: 1440
`)
	_, err := writeCooldownExclude(root, "turbo", "2.9.14")
	if err != nil {
		t.Fatalf("writeCooldownExclude: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(root, "pnpm-workspace.yaml"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	s := string(got)
	for _, want := range []string{
		`packages:`,
		`minimumReleaseAge: 1440`,
		`minimumReleaseAgeExclude:`,
		`"turbo@2.9.14"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in result:\n%s", want, s)
		}
	}
}

func TestWriteCooldownExclude_AppendToExistingList(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "pnpm-workspace.yaml", `minimumReleaseAge: 1440
minimumReleaseAgeExclude:
  - "react@19.0.1"
`)
	_, err := writeCooldownExclude(root, "turbo", "2.9.14")
	if err != nil {
		t.Fatalf("writeCooldownExclude: %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(root, "pnpm-workspace.yaml"))
	s := string(got)
	if !strings.Contains(s, `"react@19.0.1"`) {
		t.Errorf("lost existing react@19.0.1 entry:\n%s", s)
	}
	if !strings.Contains(s, `"turbo@2.9.14"`) {
		t.Errorf("missing new turbo@2.9.14 entry:\n%s", s)
	}
}

func TestWriteCooldownExclude_Idempotent(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "pnpm-workspace.yaml", `minimumReleaseAgeExclude:
  - "turbo@2.9.14"
`)
	before, _ := os.ReadFile(filepath.Join(root, "pnpm-workspace.yaml"))
	_, err := writeCooldownExclude(root, "turbo", "2.9.14")
	if err != nil {
		t.Fatalf("writeCooldownExclude: %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(root, "pnpm-workspace.yaml"))
	if string(before) != string(after) {
		t.Errorf("file changed on idempotent re-apply:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}
