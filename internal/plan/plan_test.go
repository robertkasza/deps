package plan

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/robertkasza/deps/internal/pkgmgr"
	"github.com/robertkasza/deps/internal/registry"
)

// fakeRegistry implements registry.Client for tests.
type fakeRegistry struct {
	versions  map[string][]string
	manifests map[string]map[string]registry.Manifest // pkg -> version -> manifest
}

func (f *fakeRegistry) Versions(pkg string) ([]string, error) {
	v, ok := f.versions[pkg]
	if !ok {
		return nil, fmt.Errorf("no fake versions for %s", pkg)
	}
	return v, nil
}

func (f *fakeRegistry) Manifest(pkg, version string) (registry.Manifest, error) {
	m, ok := f.manifests[pkg][version]
	if !ok {
		return registry.Manifest{}, fmt.Errorf("no fake manifest for %s@%s", pkg, version)
	}
	return m, nil
}

func writePkg(t *testing.T, dir, content string) pkgmgr.Workspace {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	pj := filepath.Join(dir, "package.json")
	if err := os.WriteFile(pj, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return pkgmgr.Workspace{Dir: dir, PackageJSON: pj}
}

func TestBuild_DirectBumpInSameMajor(t *testing.T) {
	dir := t.TempDir()
	ws := writePkg(t, dir, `{"dependencies": {"lodash": "^4.17.20"}}`)

	reg := &fakeRegistry{
		versions: map[string][]string{
			"lodash": {"4.17.20", "4.17.21", "5.0.0"},
		},
	}
	b := New(reg)
	plan, err := b.Build([]pkgmgr.Finding{
		{
			Kind: pkgmgr.FindingDirect,
			Advisory: pkgmgr.Advisory{
				GHSA: "GHSA-x", Package: "lodash",
				VulnerableRange: "<4.17.21", FixedRange: ">=4.17.21",
				Path: []string{"lodash"}, Workspace: ws,
			},
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(plan.Actionable) != 1 || len(plan.Unresolved) != 0 {
		t.Fatalf("plan: %+v", plan)
	}
	e := plan.Actionable[0]
	if e.Kind != pkgmgr.EditBumpDirect {
		t.Errorf("kind: %v", e.Kind)
	}
	if e.From != "^4.17.20" || e.To != "^4.17.21" {
		t.Errorf("from/to: %q -> %q", e.From, e.To)
	}
	if e.Field != "dependencies" {
		t.Errorf("field: %q", e.Field)
	}
}

// Two advisories on the same direct dep, fixed in different patch
// versions. Plan must emit ONE bump-direct edit whose target satisfies
// both FixedRanges (the higher floor wins), not two competing bumps.
func TestBuild_DirectGroupedAcrossAdvisories(t *testing.T) {
	dir := t.TempDir()
	ws := writePkg(t, dir, `{"dependencies": {"fast-uri": "^3.0.0"}}`)

	reg := &fakeRegistry{
		versions: map[string][]string{
			"fast-uri": {"3.0.0", "3.1.0", "3.1.1", "3.1.2", "4.0.0"},
		},
	}
	b := New(reg)
	plan, err := b.Build([]pkgmgr.Finding{
		{
			Kind: pkgmgr.FindingDirect,
			Advisory: pkgmgr.Advisory{
				GHSA: "GHSA-A", Package: "fast-uri",
				VulnerableRange: "<3.1.1", FixedRange: ">=3.1.1",
				Path: []string{"fast-uri"}, Workspace: ws,
			},
		},
		{
			Kind: pkgmgr.FindingDirect,
			Advisory: pkgmgr.Advisory{
				GHSA: "GHSA-B", Package: "fast-uri",
				VulnerableRange: "<3.1.2", FixedRange: ">=3.1.2",
				Path: []string{"fast-uri"}, Workspace: ws,
			},
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(plan.Actionable) != 1 {
		t.Fatalf("expected 1 merged bump, got %d: %+v", len(plan.Actionable), plan.Actionable)
	}
	if len(plan.Unresolved) != 0 {
		t.Fatalf("unresolved: %+v", plan.Unresolved)
	}
	e := plan.Actionable[0]
	if e.Kind != pkgmgr.EditBumpDirect {
		t.Errorf("kind: %v", e.Kind)
	}
	if e.To != "^3.1.2" {
		t.Errorf("to: want ^3.1.2 (highest floor), got %q", e.To)
	}
	// Reason must list both GHSAs so reviewers see why this single
	// edit is doing double duty.
	if !strings.Contains(e.Reason, "GHSA-A") || !strings.Contains(e.Reason, "GHSA-B") {
		t.Errorf("reason should name both GHSAs, got %q", e.Reason)
	}
}

// Mixed group: one advisory has a same-major fix, the other only has a
// fix in a newer major. The same-major bump still happens for the
// fixable one; the major-jump advisory remains unresolved.
func TestBuild_DirectGroupMixedFixability(t *testing.T) {
	dir := t.TempDir()
	ws := writePkg(t, dir, `{"dependencies": {"foo": "^3.0.0"}}`)

	reg := &fakeRegistry{
		versions: map[string][]string{
			"foo": {"3.0.0", "3.1.0", "4.0.0"},
		},
	}
	b := New(reg)
	plan, err := b.Build([]pkgmgr.Finding{
		{
			Kind: pkgmgr.FindingDirect,
			Advisory: pkgmgr.Advisory{
				GHSA: "GHSA-A", Package: "foo",
				FixedRange: ">=3.1.0",
				Path:       []string{"foo"}, Workspace: ws,
			},
		},
		{
			Kind: pkgmgr.FindingDirect,
			Advisory: pkgmgr.Advisory{
				GHSA: "GHSA-B", Package: "foo",
				FixedRange: ">=4.0.0",
				Path:       []string{"foo"}, Workspace: ws,
			},
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(plan.Actionable) != 1 {
		t.Fatalf("expected 1 actionable, got %d: %+v", len(plan.Actionable), plan.Actionable)
	}
	if plan.Actionable[0].To != "^3.1.0" {
		t.Errorf("to: want ^3.1.0, got %q", plan.Actionable[0].To)
	}
	if len(plan.Unresolved) != 1 || plan.Unresolved[0].Finding.Advisory.GHSA != "GHSA-B" ||
		plan.Unresolved[0].Reason != ReasonMajorJumpRequired {
		t.Errorf("unresolved: %+v", plan.Unresolved)
	}
}

func TestBuild_DirectMajorJumpRequired(t *testing.T) {
	dir := t.TempDir()
	ws := writePkg(t, dir, `{"dependencies": {"foo": "^1.2.0"}}`)

	reg := &fakeRegistry{
		versions: map[string][]string{
			"foo": {"1.2.0", "2.0.0"},
		},
	}
	b := New(reg)
	plan, err := b.Build([]pkgmgr.Finding{
		{
			Kind: pkgmgr.FindingDirect,
			Advisory: pkgmgr.Advisory{
				GHSA: "GHSA-x", Package: "foo",
				FixedRange: ">=2.0.0",
				Path:       []string{"foo"}, Workspace: ws,
			},
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(plan.Actionable) != 0 || len(plan.Unresolved) != 1 {
		t.Fatalf("plan: %+v", plan)
	}
	if plan.Unresolved[0].Reason != ReasonMajorJumpRequired {
		t.Errorf("reason: %q", plan.Unresolved[0].Reason)
	}
}

func TestBuild_NoFixAvailable(t *testing.T) {
	dir := t.TempDir()
	ws := writePkg(t, dir, `{"dependencies": {"request": "^2.88.2"}}`)

	b := New(&fakeRegistry{}) // never queried
	plan, err := b.Build([]pkgmgr.Finding{
		{
			Kind: pkgmgr.FindingDirect,
			Advisory: pkgmgr.Advisory{
				GHSA: "GHSA-x", Package: "request",
				FixedRange: "<0.0.0",
				Path:       []string{"request"}, Workspace: ws,
			},
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(plan.Actionable) != 0 || len(plan.Unresolved) != 1 {
		t.Fatalf("plan: %+v", plan)
	}
	if plan.Unresolved[0].Reason != ReasonNoFixAvailable {
		t.Errorf("reason: %q", plan.Unresolved[0].Reason)
	}
}

func TestBuild_TransitiveBumpParentInSameMajor(t *testing.T) {
	dir := t.TempDir()
	ws := writePkg(t, dir, `{"dependencies": {"body-parser": "^1.19.0"}}`)

	reg := &fakeRegistry{
		versions: map[string][]string{
			"body-parser": {"1.19.0", "1.20.3"},
			"qs":          {"6.7.0", "6.13.0"},
		},
		manifests: map[string]map[string]registry.Manifest{
			"body-parser": {
				"1.19.0": {Dependencies: map[string]string{"qs": "6.7.0"}},
				"1.20.3": {Dependencies: map[string]string{"qs": "6.13.0"}},
			},
		},
	}
	b := New(reg)
	plan, err := b.Build([]pkgmgr.Finding{
		{
			Kind:   pkgmgr.FindingTransitive,
			Parent: "body-parser",
			Advisory: pkgmgr.Advisory{
				GHSA: "GHSA-y", Package: "qs",
				VulnerableRange: "<6.7.3", FixedRange: ">=6.13.0",
				Path: []string{"body-parser", "qs"}, Workspace: ws,
			},
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(plan.Actionable) != 1 || len(plan.Unresolved) != 0 {
		t.Fatalf("plan: %+v", plan)
	}
	e := plan.Actionable[0]
	if e.Kind != pkgmgr.EditBumpParent {
		t.Errorf("kind: %v", e.Kind)
	}
	if e.Package != "body-parser" {
		t.Errorf("package: %q", e.Package)
	}
	if e.From != "^1.19.0" || e.To != "^1.20.3" {
		t.Errorf("from/to: %q -> %q", e.From, e.To)
	}
}

// Two advisories on the same transitive vuln pkg through the same
// parent. The latest parent version pulls in a vuln version high
// enough to clear advisory A but not advisory B. Plan must emit a
// single parent bump (covering A) AND an override (covering B), per
// the policy that prefers parent bumps over overrides whenever both
// can fix an advisory.
func TestBuild_TransitiveSplitBumpAndOverride(t *testing.T) {
	dir := t.TempDir()
	ws := writePkg(t, dir, `{"dependencies": {"ajv": "^8.0.0"}}`)
	ws.MonorepoRoot = dir

	reg := &fakeRegistry{
		versions: map[string][]string{
			"ajv":      {"8.0.0", "8.5.0"},
			"fast-uri": {"3.0.0", "3.1.1", "3.1.2"},
		},
		manifests: map[string]map[string]registry.Manifest{
			"ajv": {
				"8.0.0": {Dependencies: map[string]string{"fast-uri": "3.0.0"}},
				// Latest ajv pulls in fast-uri 3.1.1 — clears advisory A
				// (fixed in >=3.1.1) but not advisory B (>=3.1.2).
				"8.5.0": {Dependencies: map[string]string{"fast-uri": "3.1.1"}},
			},
		},
	}
	b := New(reg)
	plan, err := b.Build([]pkgmgr.Finding{
		{
			Kind:   pkgmgr.FindingTransitive,
			Parent: "ajv",
			Advisory: pkgmgr.Advisory{
				GHSA: "GHSA-A", Package: "fast-uri",
				VulnerableRange: "<3.1.1", FixedRange: ">=3.1.1",
				Path: []string{"ajv", "fast-uri"}, Workspace: ws,
			},
		},
		{
			Kind:   pkgmgr.FindingTransitive,
			Parent: "ajv",
			Advisory: pkgmgr.Advisory{
				GHSA: "GHSA-B", Package: "fast-uri",
				VulnerableRange: "<3.1.2", FixedRange: ">=3.1.2",
				Path: []string{"ajv", "fast-uri"}, Workspace: ws,
			},
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(plan.Actionable) != 2 {
		t.Fatalf("expected 2 edits (bump + override), got %d: %+v", len(plan.Actionable), plan.Actionable)
	}
	var bump, override *pkgmgr.Edit
	for i := range plan.Actionable {
		e := &plan.Actionable[i]
		switch e.Kind {
		case pkgmgr.EditBumpParent:
			bump = e
		case pkgmgr.EditOverrideAdd:
			override = e
		}
	}
	if bump == nil {
		t.Fatalf("missing bump-parent edit")
	}
	if bump.Package != "ajv" || bump.To != "^8.5.0" {
		t.Errorf("bump: %+v", bump)
	}
	if !strings.Contains(bump.Reason, "GHSA-A") || strings.Contains(bump.Reason, "GHSA-B") {
		t.Errorf("bump reason should cover GHSA-A only, got %q", bump.Reason)
	}
	if override == nil {
		t.Fatalf("missing override-add edit")
	}
	if override.Package != "fast-uri" || override.To != ">=3.1.2" {
		t.Errorf("override: %+v", override)
	}
}

func TestBuild_TransitiveOverrideFallback(t *testing.T) {
	dir := t.TempDir()
	ws := writePkg(t, dir, `{"dependencies": {"request": "^2.88.2"}}`)

	// No parent version fixes the transitive (parent is dead).
	reg := &fakeRegistry{
		versions: map[string][]string{
			"request": {"2.88.0", "2.88.2"},
		},
		manifests: map[string]map[string]registry.Manifest{
			"request": {
				"2.88.0": {Dependencies: map[string]string{"tough-cookie": "2.5.0"}},
				"2.88.2": {Dependencies: map[string]string{"tough-cookie": "2.5.0"}},
			},
		},
	}
	b := New(reg)
	plan, err := b.Build([]pkgmgr.Finding{
		{
			Kind:   pkgmgr.FindingTransitive,
			Parent: "request",
			Advisory: pkgmgr.Advisory{
				GHSA: "GHSA-z", Package: "tough-cookie",
				VulnerableRange: "<4.1.3", FixedRange: ">=4.1.3",
				Path: []string{"request", "tough-cookie"}, Workspace: ws,
			},
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(plan.Actionable) != 1 || len(plan.Unresolved) != 0 {
		t.Fatalf("plan: %+v", plan)
	}
	e := plan.Actionable[0]
	if e.Kind != pkgmgr.EditOverrideAdd {
		t.Errorf("kind: %v", e.Kind)
	}
	if e.Package != "tough-cookie" {
		t.Errorf("package: %q", e.Package)
	}
	if e.VulnerableRange != "<4.1.3" {
		t.Errorf("vulnerableRange: %q", e.VulnerableRange)
	}
	if e.To != ">=4.1.3" {
		t.Errorf("to: %q", e.To)
	}
}

// Two advisories on the same vuln package, fixed in different versions
// (the fast-uri shape: 3.1.1 and 3.1.2). Both fall to override because
// no parent version fixes them. The plan must merge into ONE override
// edit using the higher fixed target and the broader vulnerable range,
// not two conflicting edits.
func TestBuild_TransitiveOverridesMergedAcrossAdvisories(t *testing.T) {
	dir := t.TempDir()
	ws := writePkg(t, dir, `{"dependencies": {"ajv": "^8.0.0"}}`)
	ws.MonorepoRoot = dir

	reg := &fakeRegistry{
		versions: map[string][]string{
			"ajv": {"8.0.0"},
		},
		manifests: map[string]map[string]registry.Manifest{
			"ajv": {
				"8.0.0": {Dependencies: map[string]string{"fast-uri": "3.0.0"}},
			},
		},
	}
	b := New(reg)
	plan, err := b.Build([]pkgmgr.Finding{
		{
			Kind:   pkgmgr.FindingTransitive,
			Parent: "ajv",
			Advisory: pkgmgr.Advisory{
				GHSA: "GHSA-A", Package: "fast-uri",
				VulnerableRange: "<3.1.1", FixedRange: ">=3.1.1",
				Path: []string{"ajv", "fast-uri"}, Workspace: ws,
			},
		},
		{
			Kind:   pkgmgr.FindingTransitive,
			Parent: "ajv",
			Advisory: pkgmgr.Advisory{
				GHSA: "GHSA-B", Package: "fast-uri",
				VulnerableRange: "<3.1.2", FixedRange: ">=3.1.2",
				Path: []string{"ajv", "fast-uri"}, Workspace: ws,
			},
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(plan.Actionable) != 1 {
		t.Fatalf("expected 1 merged override, got %d: %+v", len(plan.Actionable), plan.Actionable)
	}
	e := plan.Actionable[0]
	if e.Kind != pkgmgr.EditOverrideAdd {
		t.Errorf("kind: %v", e.Kind)
	}
	if e.Package != "fast-uri" {
		t.Errorf("package: %q", e.Package)
	}
	if e.VulnerableRange != "<3.1.2" {
		t.Errorf("vulnerableRange: want <3.1.2 (broader), got %q", e.VulnerableRange)
	}
	if e.To != ">=3.1.2" {
		t.Errorf("to: want >=3.1.2 (higher), got %q", e.To)
	}
}

func TestBuild_TransitiveMajorJumpRequired(t *testing.T) {
	dir := t.TempDir()
	ws := writePkg(t, dir, `{"dependencies": {"foo": "^1.0.0"}}`)

	reg := &fakeRegistry{
		versions: map[string][]string{
			"foo":  {"1.0.0", "1.5.0", "2.0.0"},
			"vuln": {"1.0.0", "2.0.0"},
		},
		manifests: map[string]map[string]registry.Manifest{
			"foo": {
				"1.0.0": {Dependencies: map[string]string{"vuln": "1.0.0"}},
				"1.5.0": {Dependencies: map[string]string{"vuln": "1.0.0"}},
				"2.0.0": {Dependencies: map[string]string{"vuln": "2.0.0"}},
			},
		},
	}
	b := New(reg)
	plan, err := b.Build([]pkgmgr.Finding{
		{
			Kind:   pkgmgr.FindingTransitive,
			Parent: "foo",
			Advisory: pkgmgr.Advisory{
				GHSA: "GHSA-w", Package: "vuln",
				FixedRange: ">=2.0.0",
				Path:       []string{"foo", "vuln"}, Workspace: ws,
			},
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(plan.Actionable) != 0 || len(plan.Unresolved) != 1 {
		t.Fatalf("plan: %+v", plan)
	}
	if plan.Unresolved[0].Reason != ReasonMajorJumpRequired {
		t.Errorf("reason: %q", plan.Unresolved[0].Reason)
	}
}

func TestBuild_PreservesOperator(t *testing.T) {
	cases := []struct {
		current, want string
	}{
		{"^4.17.20", "^4.17.21"},
		{"~4.17.20", "~4.17.21"},
		{"4.17.20", "4.17.21"},
		{">=4.17.20", ">=4.17.21"},
	}
	for _, tc := range cases {
		t.Run(tc.current, func(t *testing.T) {
			dir := t.TempDir()
			ws := writePkg(t, dir, fmt.Sprintf(`{"dependencies": {"lodash": "%s"}}`, tc.current))

			reg := &fakeRegistry{versions: map[string][]string{"lodash": {"4.17.20", "4.17.21"}}}
			b := New(reg)
			plan, err := b.Build([]pkgmgr.Finding{
				{
					Kind: pkgmgr.FindingDirect,
					Advisory: pkgmgr.Advisory{
						GHSA: "G", Package: "lodash",
						FixedRange: ">=4.17.21",
						Path:       []string{"lodash"}, Workspace: ws,
					},
				},
			})
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			if len(plan.Actionable) != 1 {
				t.Fatalf("plan: %+v", plan)
			}
			if plan.Actionable[0].To != tc.want {
				t.Errorf("to: got %q, want %q", plan.Actionable[0].To, tc.want)
			}
		})
	}
}
