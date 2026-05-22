package plan

import (
	"testing"

	"github.com/robertkasza/deps/internal/pkgmgr"
	"github.com/robertkasza/deps/internal/registry"
)

// fakeTree is an in-test TreeInspector. Keyed by (pkg, vulnRange);
// callers register the edges they want the inspector to return.
type fakeTree struct {
	edges map[string][]pkgmgr.ImporterEdge
}

func (f *fakeTree) ImportersOfRange(ws pkgmgr.Workspace, pkg, vulnRange string) []pkgmgr.ImporterEdge {
	return f.edges[pkg+"|"+vulnRange]
}

// Cooldown-bypass succeeds: parent bump unavailable (parent is dead),
// cooldown is active, and every importer's range permits the patched
// version. Plan should emit EditExcludeFromCooldown instead of an
// override.
func TestBuild_CooldownBypass_Viable(t *testing.T) {
	dir := t.TempDir()
	ws := writePkg(t, dir, `{"dependencies": {"request": "^2.88.2"}}`)
	ws.MonorepoRoot = dir

	reg := &fakeRegistry{
		versions: map[string][]string{
			// Parent has no newer version, so no parent bump.
			"request": {"2.88.0", "2.88.2"},
			// tough-cookie has a fix at 2.5.1 (the lowest satisfying).
			"tough-cookie": {"2.5.0", "2.5.1", "4.1.3"},
		},
		manifests: map[string]map[string]registry.Manifest{
			"request": {
				"2.88.2": {Dependencies: map[string]string{"tough-cookie": "^2.4.0"}},
			},
		},
	}
	tree := &fakeTree{
		edges: map[string][]pkgmgr.ImporterEdge{
			"tough-cookie|<2.5.1": {
				{ImporterName: "request", ImporterVersion: "2.88.2"},
			},
		},
	}
	b := New(reg)
	b.Tree = tree
	b.CooldownActive = true

	plan, err := b.Build([]pkgmgr.Finding{{
		Kind:   pkgmgr.FindingTransitive,
		Parent: "request",
		Advisory: pkgmgr.Advisory{
			GHSA: "GHSA-c1", Package: "tough-cookie",
			VulnerableRange: "<2.5.1", FixedRange: ">=2.5.1",
			Path: []string{"request", "tough-cookie"}, Workspace: ws,
		},
	}})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(plan.Actionable) != 1 || len(plan.Unresolved) != 0 {
		t.Fatalf("plan: %+v", plan)
	}
	e := plan.Actionable[0]
	if e.Kind != pkgmgr.EditExcludeFromCooldown {
		t.Errorf("kind: want exclude-from-cooldown, got %q", e.Kind)
	}
	if e.Package != "tough-cookie" {
		t.Errorf("package: %q", e.Package)
	}
	if e.To != "2.5.1" {
		t.Errorf("to: want 2.5.1 (lowest satisfying), got %q", e.To)
	}
}

// Cooldown-bypass blocked by an exact pin elsewhere in the tree.
// Plan must fall through to override.
func TestBuild_CooldownBypass_BlockedByExactPin(t *testing.T) {
	dir := t.TempDir()
	ws := writePkg(t, dir, `{"dependencies": {"request": "^2.88.2"}}`)
	ws.MonorepoRoot = dir

	reg := &fakeRegistry{
		versions: map[string][]string{
			"request":      {"2.88.0", "2.88.2"},
			"other-parent": {"1.0.0"},
			"tough-cookie": {"2.5.0", "2.5.1"},
		},
		manifests: map[string]map[string]registry.Manifest{
			"request": {
				"2.88.2": {Dependencies: map[string]string{"tough-cookie": "^2.4.0"}},
			},
			"other-parent": {
				// Exact pin to the vulnerable version — kills the bypass.
				"1.0.0": {Dependencies: map[string]string{"tough-cookie": "2.5.0"}},
			},
		},
	}
	tree := &fakeTree{
		edges: map[string][]pkgmgr.ImporterEdge{
			"tough-cookie|<2.5.1": {
				{ImporterName: "request", ImporterVersion: "2.88.2"},
				{ImporterName: "other-parent", ImporterVersion: "1.0.0"},
			},
		},
	}
	b := New(reg)
	b.Tree = tree
	b.CooldownActive = true

	plan, err := b.Build([]pkgmgr.Finding{{
		Kind:   pkgmgr.FindingTransitive,
		Parent: "request",
		Advisory: pkgmgr.Advisory{
			GHSA: "GHSA-c2", Package: "tough-cookie",
			VulnerableRange: "<2.5.1", FixedRange: ">=2.5.1",
			Path: []string{"request", "tough-cookie"}, Workspace: ws,
		},
	}})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(plan.Actionable) != 1 {
		t.Fatalf("expected 1 edit, got %d: %+v", len(plan.Actionable), plan.Actionable)
	}
	if plan.Actionable[0].Kind != pkgmgr.EditOverrideAdd {
		t.Errorf("kind: want override-add (fallback), got %q", plan.Actionable[0].Kind)
	}
}

// Cooldown inactive → bypass rung skipped entirely. Plan falls
// straight through to override even when the importer ranges would
// allow it.
func TestBuild_CooldownBypass_SkippedWhenInactive(t *testing.T) {
	dir := t.TempDir()
	ws := writePkg(t, dir, `{"dependencies": {"request": "^2.88.2"}}`)
	ws.MonorepoRoot = dir

	reg := &fakeRegistry{
		versions: map[string][]string{
			"request":      {"2.88.0", "2.88.2"},
			"tough-cookie": {"2.5.0", "2.5.1"},
		},
		manifests: map[string]map[string]registry.Manifest{
			"request": {
				"2.88.2": {Dependencies: map[string]string{"tough-cookie": "^2.4.0"}},
			},
		},
	}
	tree := &fakeTree{
		edges: map[string][]pkgmgr.ImporterEdge{
			"tough-cookie|<2.5.1": {
				{ImporterName: "request", ImporterVersion: "2.88.2"},
			},
		},
	}
	b := New(reg)
	b.Tree = tree
	b.CooldownActive = false // off

	plan, err := b.Build([]pkgmgr.Finding{{
		Kind:   pkgmgr.FindingTransitive,
		Parent: "request",
		Advisory: pkgmgr.Advisory{
			GHSA: "GHSA-c3", Package: "tough-cookie",
			VulnerableRange: "<2.5.1", FixedRange: ">=2.5.1",
			Path: []string{"request", "tough-cookie"}, Workspace: ws,
		},
	}})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(plan.Actionable) != 1 {
		t.Fatalf("expected 1 edit, got %d: %+v", len(plan.Actionable), plan.Actionable)
	}
	if plan.Actionable[0].Kind != pkgmgr.EditOverrideAdd {
		t.Errorf("kind: want override-add when cooldown off, got %q", plan.Actionable[0].Kind)
	}
}
