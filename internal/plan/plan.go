// Package plan walks the SKILL.md remediation ladder over triaged
// findings and produces a Plan: actionable Edits + unresolved findings.
//
// The ladder, per finding:
//
//   Direct:
//     1. fix in same major as current pin     -> bump-direct
//     2. only major-bump fixes                -> unresolved{major-jump-required}
//     3. no fix published                     -> unresolved{no-fix-available}
//
//   Transitive:
//     1. parent has fix in same major (registry-validated) -> bump-parent
//     2. only parent-major-bump fixes                       -> unresolved{major-jump-required}
//     3. no parent fix at all                               -> override-add (or override-consolidate)
//     4. no patched version of vuln pkg published anywhere  -> unresolved{no-fix-available}
//
// Plan operates on package-manager-agnostic types from internal/pkgmgr
// and consults internal/registry for parent-bump candidate version data.
package plan

import (
	"fmt"
	"path/filepath"

	"github.com/Masterminds/semver/v3"

	"github.com/robertkasza/deps/internal/pkgmgr"
	"github.com/robertkasza/deps/internal/registry"
)

// Reasons reported on Unresolved entries.
const (
	ReasonNoFixAvailable    = "no-fix-available"
	ReasonMajorJumpRequired = "major-jump-required"
	ReasonParentNotInDeps   = "parent-not-in-deps"
)

// Builder produces Plans from triaged findings.
type Builder struct {
	Registry registry.Client
}

// New returns a Builder using the given registry client.
func New(reg registry.Client) *Builder { return &Builder{Registry: reg} }

// Build walks the remediation ladder for each finding.
func (b *Builder) Build(findings []pkgmgr.Finding) (pkgmgr.Plan, error) {
	cache := manifestCache{}
	plan := pkgmgr.Plan{}

	// Track existing root overrides to detect consolidation. Only for
	// future use; MVP emits override-add and never -consolidate.

	for _, f := range findings {
		// Cheap pre-check: no patched version published anywhere.
		if isNoFix(f.Advisory.FixedRange) {
			plan.Unresolved = append(plan.Unresolved, pkgmgr.Unresolved{
				Finding: f, Reason: ReasonNoFixAvailable,
			})
			continue
		}

		switch f.Kind {
		case pkgmgr.FindingDirect:
			edit, reason, err := b.planDirect(f, cache)
			if err != nil {
				return plan, err
			}
			if reason != "" {
				plan.Unresolved = append(plan.Unresolved, pkgmgr.Unresolved{Finding: f, Reason: reason})
			} else {
				plan.Actionable = append(plan.Actionable, edit)
			}

		case pkgmgr.FindingTransitive:
			edit, reason, err := b.planTransitive(f, cache)
			if err != nil {
				return plan, err
			}
			if reason != "" {
				plan.Unresolved = append(plan.Unresolved, pkgmgr.Unresolved{Finding: f, Reason: reason})
			} else {
				plan.Actionable = append(plan.Actionable, edit)
			}

		default:
			return plan, fmt.Errorf("unknown finding kind %q", f.Kind)
		}
	}
	return plan, nil
}

// isNoFix reports whether the advisory's patched_versions string
// indicates no fix has been published.
func isNoFix(fixedRange string) bool {
	switch fixedRange {
	case "", "<0.0.0":
		return true
	}
	return false
}

// planDirect handles direct findings: bump the workspace's pin into
// the fixed range while preserving the original operator and major.
func (b *Builder) planDirect(f pkgmgr.Finding, cache manifestCache) (pkgmgr.Edit, string, error) {
	pkg := f.Advisory.Package

	manifest, err := cache.get(f.Advisory.Workspace)
	if err != nil {
		return pkgmgr.Edit{}, "", err
	}

	current, field, ok := manifest.findDep(pkg)
	if !ok {
		// triage thought this was direct but the manifest doesn't list it.
		return pkgmgr.Edit{}, ReasonParentNotInDeps, nil
	}

	op := constraintOperator(current)
	anchor := extractAnchor(current)
	if anchor == nil {
		return pkgmgr.Edit{}, "", fmt.Errorf("cannot parse current constraint %q for %s", current, pkg)
	}

	fixed, err := semver.NewConstraint(f.Advisory.FixedRange)
	if err != nil {
		return pkgmgr.Edit{}, "", fmt.Errorf("parse fixed range %q for %s: %w", f.Advisory.FixedRange, pkg, err)
	}

	versions, err := b.Registry.Versions(pkg)
	if err != nil {
		return pkgmgr.Edit{}, "", fmt.Errorf("registry %s: %w", pkg, err)
	}

	target, ok := pickSmallest(versions, fixed, anchor)
	if !ok {
		if hasMajorBumpFix(versions, fixed, anchor) {
			return pkgmgr.Edit{}, ReasonMajorJumpRequired, nil
		}
		return pkgmgr.Edit{}, ReasonNoFixAvailable, nil
	}

	return pkgmgr.Edit{
		Kind:    pkgmgr.EditBumpDirect,
		File:    f.Advisory.Workspace.PackageJSON,
		Package: pkg,
		Field:   string(field),
		From:    current,
		To:      applyOperator(op, target),
		Reason:  fmt.Sprintf("fixes %s (%s)", f.Advisory.GHSA, f.Advisory.Package),
	}, "", nil
}

// planTransitive handles transitive findings: try parent bump first,
// fall back to a root override if no parent version fixes the vuln.
func (b *Builder) planTransitive(f pkgmgr.Finding, cache manifestCache) (pkgmgr.Edit, string, error) {
	parent := f.Parent
	vuln := f.Advisory.Package

	manifest, err := cache.get(f.Advisory.Workspace)
	if err != nil {
		return pkgmgr.Edit{}, "", err
	}

	currentParent, field, ok := manifest.findDep(parent)
	if !ok {
		// Parent isn't in this workspace's manifest. Could be a transitive
		// chain longer than 2; for MVP fall through to override.
		return b.planOverride(f), "", nil
	}

	op := constraintOperator(currentParent)
	anchor := extractAnchor(currentParent)
	if anchor == nil {
		return pkgmgr.Edit{}, "", fmt.Errorf("cannot parse parent constraint %q for %s", currentParent, parent)
	}

	fixedVuln, err := semver.NewConstraint(f.Advisory.FixedRange)
	if err != nil {
		return pkgmgr.Edit{}, "", fmt.Errorf("parse fixed range %q for %s: %w", f.Advisory.FixedRange, vuln, err)
	}

	versions, err := b.Registry.Versions(parent)
	if err != nil {
		return pkgmgr.Edit{}, "", fmt.Errorf("registry %s: %w", parent, err)
	}

	// Find a parent version whose declared dep on `vuln` falls in the fixed range.
	candidate, fixesInMajor, err := b.findParentFix(parent, versions, anchor, vuln, fixedVuln, true)
	if err != nil {
		return pkgmgr.Edit{}, "", err
	}
	if candidate != nil {
		return pkgmgr.Edit{
			Kind:    pkgmgr.EditBumpParent,
			File:    f.Advisory.Workspace.PackageJSON,
			Package: parent,
			Field:   string(field),
			From:    currentParent,
			To:      applyOperator(op, candidate),
			Reason:  fmt.Sprintf("patches transitive %s (%s)", vuln, f.Advisory.GHSA),
		}, "", nil
	}

	if fixesInMajor {
		// Shouldn't happen given earlier branch, defensive.
		return pkgmgr.Edit{}, ReasonMajorJumpRequired, nil
	}

	// Try a major bump of the parent — does any newer-major parent fix the vuln?
	if newerMajor, _, err := b.findParentFix(parent, versions, anchor, vuln, fixedVuln, false); err != nil {
		return pkgmgr.Edit{}, "", err
	} else if newerMajor != nil {
		return pkgmgr.Edit{}, ReasonMajorJumpRequired, nil
	}

	// No parent version (any major) fixes it -> override fallback.
	return b.planOverride(f), "", nil
}

// findParentFix walks parent versions looking for the smallest one
// whose dep on `vuln` lies in fixed. If sameMajor is true, only
// considers parent versions sharing anchor's major; otherwise only
// considers strictly-greater majors.
//
// Returns the chosen version (nil if none), and a boolean noting
// whether any candidate satisfied (used by the caller as a tiebreak —
// currently always false on success).
func (b *Builder) findParentFix(
	parent string,
	versions []string,
	anchor *semver.Version,
	vuln string,
	fixed *semver.Constraints,
	sameMajor bool,
) (*semver.Version, bool, error) {
	var candidates []*semver.Version
	for _, raw := range versions {
		v, err := semver.NewVersion(raw)
		if err != nil {
			continue
		}
		if v.Prerelease() != "" {
			continue
		}
		if sameMajor {
			if v.Major() != anchor.Major() {
				continue
			}
			if !v.GreaterThan(anchor) {
				continue
			}
		} else {
			if v.Major() <= anchor.Major() {
				continue
			}
		}
		candidates = append(candidates, v)
	}

	// Sort smallest-first.
	for i := 0; i < len(candidates); i++ {
		for j := i + 1; j < len(candidates); j++ {
			if candidates[j].LessThan(candidates[i]) {
				candidates[i], candidates[j] = candidates[j], candidates[i]
			}
		}
	}

	for _, v := range candidates {
		m, err := b.Registry.Manifest(parent, v.Original())
		if err != nil {
			return nil, false, fmt.Errorf("registry manifest %s@%s: %w", parent, v.Original(), err)
		}
		declared, ok := m.Dependencies[vuln]
		if !ok {
			// Parent version no longer pulls in vuln at all -> still a fix.
			return v, false, nil
		}
		// If the parent's declared dep range is fully inside the fixed range,
		// we know the resolved sub-dep can't be vulnerable. Approximate by
		// treating the lower bound of the parent's declared range as the
		// resolution outcome.
		if anchor := extractAnchor(declared); anchor != nil && fixed.Check(anchor) {
			return v, false, nil
		}
	}
	return nil, false, nil
}

// planOverride builds an EditOverrideAdd targeting the monorepo root's
// package.json (where pnpm.overrides live, per SKILL.md). For MVP we
// always emit override-add; consolidation is future work, and writing
// to pnpm-workspace.yaml's `overrides:` (modern pnpm) instead of the
// root package.json is apply's problem.
func (b *Builder) planOverride(f pkgmgr.Finding) pkgmgr.Edit {
	root := f.Advisory.Workspace.MonorepoRoot
	if root == "" {
		// Defensive fallback; a Workspace without MonorepoRoot is from an
		// older code path. Use the workspace's own package.json.
		return pkgmgr.Edit{
			Kind:            pkgmgr.EditOverrideAdd,
			File:            f.Advisory.Workspace.PackageJSON,
			Package:         f.Advisory.Package,
			VulnerableRange: f.Advisory.VulnerableRange,
			To:              minVersionFromFixed(f.Advisory.FixedRange),
			Reason:          fmt.Sprintf("override transitive %s (%s)", f.Advisory.Package, f.Advisory.GHSA),
		}
	}
	return pkgmgr.Edit{
		Kind:            pkgmgr.EditOverrideAdd,
		File:            filepath.Join(root, "package.json"),
		Package:         f.Advisory.Package,
		VulnerableRange: f.Advisory.VulnerableRange,
		To:              minVersionFromFixed(f.Advisory.FixedRange),
		Reason:          fmt.Sprintf("override transitive %s (%s)", f.Advisory.Package, f.Advisory.GHSA),
	}
}

// minVersionFromFixed extracts the lower bound from a simple
// patched_versions string. Best-effort; if the range is compound or
// unparseable, returns the raw string.
func minVersionFromFixed(fixed string) string {
	if v := extractAnchor(fixed); v != nil {
		return ">=" + v.Original()
	}
	return fixed
}
