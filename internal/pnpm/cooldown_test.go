package pnpm

import (
	"testing"
)

func TestCooldownActive_WorkspaceYAMLPositive(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "pnpm-workspace.yaml", `
packages:
  - "apps/*"
minimumReleaseAge: 1440
`)
	a := New().WithRunner(failingRunner(t)) // version should not be queried
	ok, err := a.CooldownActive(root)
	if err != nil {
		t.Fatalf("CooldownActive: %v", err)
	}
	if !ok {
		t.Error("expected cooldown active when minimumReleaseAge > 0")
	}
}

func TestCooldownActive_WorkspaceYAMLZero(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "pnpm-workspace.yaml", `
minimumReleaseAge: 0
`)
	a := New().WithRunner(failingRunner(t))
	ok, err := a.CooldownActive(root)
	if err != nil {
		t.Fatalf("CooldownActive: %v", err)
	}
	if ok {
		t.Error("expected cooldown inactive when minimumReleaseAge == 0")
	}
}

func TestCooldownActive_NoYAML_Pnpm11(t *testing.T) {
	root := t.TempDir()
	runner, _ := fakeRunner([]byte("11.5.0\n"), nil, 0, nil)
	a := New().WithRunner(runner)
	ok, err := a.CooldownActive(root)
	if err != nil {
		t.Fatalf("CooldownActive: %v", err)
	}
	if !ok {
		t.Error("expected cooldown active by default on pnpm 11")
	}
}

func TestCooldownActive_NoYAML_Pnpm10(t *testing.T) {
	root := t.TempDir()
	runner, _ := fakeRunner([]byte("10.16.0\n"), nil, 0, nil)
	a := New().WithRunner(runner)
	ok, err := a.CooldownActive(root)
	if err != nil {
		t.Fatalf("CooldownActive: %v", err)
	}
	if ok {
		t.Error("expected cooldown inactive by default on pnpm 10")
	}
}

func TestCooldownActive_YAMLPresentNoKey_FallsBackToVersion(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "pnpm-workspace.yaml", `
packages:
  - "apps/*"
`)
	runner, _ := fakeRunner([]byte("11.5.0\n"), nil, 0, nil)
	a := New().WithRunner(runner)
	ok, err := a.CooldownActive(root)
	if err != nil {
		t.Fatalf("CooldownActive: %v", err)
	}
	if !ok {
		t.Error("expected fallback to pnpm version when yaml omits the key")
	}
}

// failingRunner returns a Runner that fails the test if invoked. Use
// when the test expects the cooldown decision to be made without ever
// shelling out to pnpm.
func failingRunner(t *testing.T) Runner {
	t.Helper()
	return func(dir, name string, args ...string) ([]byte, []byte, int, error) {
		t.Fatalf("unexpected exec: %s %v", name, args)
		return nil, nil, 0, nil
	}
}
