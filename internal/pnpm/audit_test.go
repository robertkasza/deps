package pnpm

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/robertkasza/deps/internal/pkgmgr"
)

// fakeRunner returns a Runner that captures invocations and returns
// canned bytes. Useful for testing Audit without a real pnpm binary.
func fakeRunner(stdout, stderr []byte, exitCode int, runErr error) (Runner, *fakeRunInvocation) {
	inv := &fakeRunInvocation{}
	return func(dir, name string, args ...string) ([]byte, []byte, int, error) {
		inv.Dir = dir
		inv.Name = name
		inv.Args = args
		return stdout, stderr, exitCode, runErr
	}, inv
}

type fakeRunInvocation struct {
	Dir  string
	Name string
	Args []string
}

func TestAudit_HappyPath(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "audit_vuln-test.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	runner, inv := fakeRunner(data, nil, 1 /* pnpm exits 1 when vulns present */, nil)
	a := New().WithRunner(runner)

	ws := pkgmgr.Workspace{
		Dir:    "/fake/repo/apps/admin",
		RelDir: "apps/admin",
		Name:   "@vuln-test/admin",
	}
	advs, err := a.Audit(ws)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if len(advs) == 0 {
		t.Errorf("expected advisories, got none")
	}
	if inv.Dir != ws.Dir {
		t.Errorf("runner dir: got %q, want %q", inv.Dir, ws.Dir)
	}
	if inv.Name != "pnpm" || len(inv.Args) < 2 || inv.Args[0] != "audit" || inv.Args[1] != "--json" {
		t.Errorf("runner cmdline: got %q %v, want pnpm audit --json", inv.Name, inv.Args)
	}
}

func TestAudit_RunnerLaunchError(t *testing.T) {
	runner, _ := fakeRunner(nil, []byte("pnpm: command not found"), -1, errors.New("exec: pnpm not found"))
	a := New().WithRunner(runner)

	_, err := a.Audit(pkgmgr.Workspace{Dir: "/fake"})
	if err == nil {
		t.Errorf("expected error from runner launch failure")
	}
}

func TestAudit_EmptyOutput(t *testing.T) {
	runner, _ := fakeRunner(nil, []byte("some stderr"), 0, nil)
	a := New().WithRunner(runner)

	_, err := a.Audit(pkgmgr.Workspace{Dir: "/fake"})
	if err == nil {
		t.Errorf("expected error on empty stdout")
	}
}

func TestAudit_NoVulns(t *testing.T) {
	// pnpm audit on a clean tree returns {"advisories":{},...} and exits 0.
	runner, _ := fakeRunner([]byte(`{"advisories":{}}`), nil, 0, nil)
	a := New().WithRunner(runner)

	advs, err := a.Audit(pkgmgr.Workspace{Dir: "/fake", IsRoot: true})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if len(advs) != 0 {
		t.Errorf("expected 0 advisories, got %d", len(advs))
	}
}
