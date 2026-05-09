package pnpm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/robertkasza/deps/internal/pkgmgr"
)

func TestApplyEdits_BumpDirect(t *testing.T) {
	root := t.TempDir()
	pj := writeFile(t, root, "package.json", `{
  "dependencies": {
    "lodash": "^4.17.20"
  }
}
`)
	a := New()
	err := a.ApplyEdits([]pkgmgr.Edit{
		{
			Kind:    pkgmgr.EditBumpDirect,
			File:    pj,
			Package: "lodash",
			Field:   "dependencies",
			From:    "^4.17.20",
			To:      "^4.17.21",
		},
	})
	if err != nil {
		t.Fatalf("ApplyEdits: %v", err)
	}
	got, _ := os.ReadFile(pj)
	if !strings.Contains(string(got), `"lodash": "^4.17.21"`) {
		t.Errorf("not bumped: %s", got)
	}
}

func TestApplyEdits_CoalescesSamePackage(t *testing.T) {
	root := t.TempDir()
	pj := writeFile(t, root, "package.json", `{
  "dependencies": {
    "lodash": "^4.17.20"
  }
}
`)
	a := New()
	// Three edits for the same lodash, increasing target versions.
	// Highest (4.18.0) should win.
	err := a.ApplyEdits([]pkgmgr.Edit{
		{Kind: pkgmgr.EditBumpDirect, File: pj, Package: "lodash", Field: "dependencies", To: "^4.17.21"},
		{Kind: pkgmgr.EditBumpDirect, File: pj, Package: "lodash", Field: "dependencies", To: "^4.18.0"},
		{Kind: pkgmgr.EditBumpDirect, File: pj, Package: "lodash", Field: "dependencies", To: "^4.17.23"},
	})
	if err != nil {
		t.Fatalf("ApplyEdits: %v", err)
	}
	got, _ := os.ReadFile(pj)
	if !strings.Contains(string(got), `"lodash": "^4.18.0"`) {
		t.Errorf("expected 4.18.0 to win: %s", got)
	}
}

func TestApplyEdits_OverrideAdd(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"name": "demo"}`+"\n")
	writeFile(t, root, "pnpm-workspace.yaml", "packages:\n  - apps/*\n")

	a := New()
	err := a.ApplyEdits([]pkgmgr.Edit{
		{
			Kind:            pkgmgr.EditOverrideAdd,
			File:            filepath.Join(root, "package.json"),
			Package:         "tough-cookie",
			VulnerableRange: "<4.1.3",
			To:              ">=4.1.3",
		},
	})
	if err != nil {
		t.Fatalf("ApplyEdits: %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(root, "package.json"))
	if !strings.Contains(string(got), `"tough-cookie@<4.1.3"`) {
		t.Errorf("override missing: %s", got)
	}
}

func TestInstall_LockfileOnly(t *testing.T) {
	runner, inv := fakeRunner([]byte("ok"), nil, 0, nil)
	a := New().WithRunner(runner)
	if err := a.Install("/some/root", true); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if inv.Dir != "/some/root" {
		t.Errorf("dir: %q", inv.Dir)
	}
	if inv.Name != "pnpm" {
		t.Errorf("cmd: %q", inv.Name)
	}
	want := []string{"install", "--lockfile-only"}
	if len(inv.Args) != 2 || inv.Args[0] != want[0] || inv.Args[1] != want[1] {
		t.Errorf("args: %v, want %v", inv.Args, want)
	}
}

func TestInstall_FullInstall(t *testing.T) {
	runner, inv := fakeRunner(nil, nil, 0, nil)
	a := New().WithRunner(runner)
	if err := a.Install("/some/root", false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if len(inv.Args) != 1 || inv.Args[0] != "install" {
		t.Errorf("args: %v, want [install]", inv.Args)
	}
}

func TestInstall_NonZeroExit(t *testing.T) {
	runner, _ := fakeRunner(nil, []byte("registry timeout"), 1, nil)
	a := New().WithRunner(runner)
	err := a.Install("/x", true)
	if err == nil {
		t.Fatalf("expected error on non-zero exit")
	}
	if !strings.Contains(err.Error(), "registry timeout") {
		t.Errorf("error doesn't include stderr: %v", err)
	}
}
