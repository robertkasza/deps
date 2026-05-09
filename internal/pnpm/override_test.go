package pnpm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteOverride_TargetsExistingYAML(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"name": "demo"}`+"\n")
	writeFile(t, root, "pnpm-workspace.yaml", `packages:
  - apps/*
overrides:
  existing: ">=1.0.0"
`)
	file, err := writeOverride(root, "tough-cookie", "<4.1.3", ">=4.1.3")
	if err != nil {
		t.Fatalf("writeOverride: %v", err)
	}
	if filepath.Base(file) != "pnpm-workspace.yaml" {
		t.Errorf("wrote to %s, expected pnpm-workspace.yaml", file)
	}
	got, _ := os.ReadFile(file)
	if !strings.Contains(string(got), `tough-cookie@<4.1.3`) {
		t.Errorf("override missing in YAML:\n%s", got)
	}
	if !strings.Contains(string(got), `existing`) {
		t.Errorf("existing key removed:\n%s", got)
	}
}

func TestWriteOverride_TargetsExistingPkgJSON(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{
  "name": "demo",
  "pnpm": {
    "overrides": {
      "existing@<1.0.0": ">=1.0.0"
    }
  }
}
`)
	writeFile(t, root, "pnpm-workspace.yaml", "packages:\n  - apps/*\n")

	file, err := writeOverride(root, "qs", "<6.14.1", ">=6.14.1")
	if err != nil {
		t.Fatalf("writeOverride: %v", err)
	}
	if filepath.Base(file) != "package.json" {
		t.Errorf("wrote to %s, expected package.json", file)
	}
	got, _ := os.ReadFile(file)
	if !strings.Contains(string(got), `"qs@<6.14.1": ">=6.14.1"`) {
		t.Errorf("override missing in package.json:\n%s", got)
	}
	if !strings.Contains(string(got), `"existing@<1.0.0"`) {
		t.Errorf("existing key removed:\n%s", got)
	}
}

func TestWriteOverride_DefaultsToPkgJSONWhenNeitherExists(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{
  "name": "demo"
}
`)
	writeFile(t, root, "pnpm-workspace.yaml", "packages:\n  - apps/*\n")

	file, err := writeOverride(root, "qs", "<6.14.1", ">=6.14.1")
	if err != nil {
		t.Fatalf("writeOverride: %v", err)
	}
	if filepath.Base(file) != "package.json" {
		t.Errorf("wrote to %s, expected package.json (default)", file)
	}
	got, _ := os.ReadFile(file)
	if !strings.Contains(string(got), `"qs@<6.14.1": ">=6.14.1"`) {
		t.Errorf("override missing:\n%s", got)
	}
}

func TestWriteOverride_ReplacesExistingKey(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"name": "demo"}`+"\n")
	writeFile(t, root, "pnpm-workspace.yaml", `packages:
  - apps/*
overrides:
  qs@<6.0.0: ">=6.0.0"
`)
	if _, err := writeOverride(root, "qs", "<6.0.0", ">=6.5.0"); err != nil {
		t.Fatalf("writeOverride: %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(root, "pnpm-workspace.yaml"))
	// Should contain the new value, only one entry for the same key.
	if strings.Count(string(got), `qs@<6.0.0`) != 1 {
		t.Errorf("expected one entry for qs@<6.0.0:\n%s", got)
	}
	if !strings.Contains(string(got), `>=6.5.0`) {
		t.Errorf("new value missing:\n%s", got)
	}
}

func TestHasYAMLOverrides(t *testing.T) {
	dir := t.TempDir()
	withOverrides := writeFile(t, dir, "with.yaml", "overrides:\n  x: y\n")
	withoutOverrides := writeFile(t, dir, "without.yaml", "packages:\n  - apps/*\n")
	missing := filepath.Join(dir, "missing.yaml")

	if !hasYAMLOverrides(withOverrides) {
		t.Errorf("hasYAMLOverrides(with): want true")
	}
	if hasYAMLOverrides(withoutOverrides) {
		t.Errorf("hasYAMLOverrides(without): want false")
	}
	if hasYAMLOverrides(missing) {
		t.Errorf("hasYAMLOverrides(missing): want false")
	}
}

func TestHasPkgJSONOverrides(t *testing.T) {
	dir := t.TempDir()
	with := writeFile(t, dir, "with.json", `{"pnpm": {"overrides": {"x": "y"}}}`)
	without := writeFile(t, dir, "without.json", `{"name": "demo"}`)
	if !hasPkgJSONOverrides(with) {
		t.Errorf("hasPkgJSONOverrides(with): want true")
	}
	if hasPkgJSONOverrides(without) {
		t.Errorf("hasPkgJSONOverrides(without): want false")
	}
}
