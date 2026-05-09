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

	// chain is the full dep path from parent down to vuln, e.g.
	// [@scalar/openapi-parser, ajv, fast-uri]. f.Advisory.Path includes
	// the parent at index 0; chain is everything after.
	chain := f.Advisory.Path
	if len(chain) > 0 && chain[0] == parent {
		chain = chain[1:]
	}

	// Find a parent version whose dep tree resolves the vuln pkg to a
	// fixed version (walking the chain at each candidate).
	candidate, predicted, err := b.findParentFix(parent, versions, anchor, chain, fixedVuln, true)
	if err != nil {
		return pkgmgr.Edit{}, "", err
	}
	if candidate != nil {
		reason := fmt.Sprintf("predicted to patch transitive %s (chain no longer reaches it; %s)",
			vuln, f.Advisory.GHSA)
		if predicted != nil {
			reason = fmt.Sprintf("predicted to patch transitive %s (resolves to %s@%s; %s)",
				vuln, vuln, predicted.Original(), f.Advisory.GHSA)
		}
		return pkgmgr.Edit{
			Kind:    pkgmgr.EditBumpParent,
			File:    f.Advisory.Workspace.PackageJSON,
			Package: parent,
			Field:   string(field),
			From:    currentParent,
			To:      applyOperator(op, candidate),
			Reason:  reason,
		}, "", nil
	}

	// Try a major bump of the parent — does any newer-major parent fix the vuln?
	newerMajor, _, err := b.findParentFix(parent, versions, anchor, chain, fixedVuln, false)
	if err != nil {
		return pkgmgr.Edit{}, "", err
	}
	if newerMajor != nil {
		return pkgmgr.Edit{}, ReasonMajorJumpRequired, nil
	}

	// No parent version (any major) fixes it -> override fallback.
	return b.planOverride(f), "", nil
}

// findParentFix picks the latest non-prerelease parent version in the
// requested band (same major, or strictly-greater major), then walks
// the dep chain from that version to check if the vuln package
// resolves to a fixed version.
//
// We don't search smaller versions because vuln fixes propagate
// forward in time: once the upstream vuln package shipped a fix and
// each intermediate updated its dep range, only versions released
// after that point can carry the fix. Older versions of the parent
// can't possibly include a fix in their transitive tree.
//
// Returns the chosen parent version and the predicted resolved
// version of the vuln at the end of the chain. predictedVuln is nil
// when the chain breaks before reaching the vuln (the vuln is no
// longer transitively pulled in at all).
func (b *Builder) findParentFix(
	parent string,
	versions []string,
	anchor *semver.Version,
	chain []string,
	fixed *semver.Constraints,
	sameMajor bool,
) (parentVer *semver.Version, predictedVuln *semver.Version, err error) {
	var latest *semver.Version
	for _, raw := range versions {
		v, perr := semver.NewVersion(raw)
		if perr != nil {
			continue
		}
		if v.Prerelease() != "" {
			continue
		}
		if sameMajor {
			if v.Major() != anchor.Major() || !v.GreaterThan(anchor) {
				continue
			}
		} else if v.Major() <= anchor.Major() {
			continue
		}
		if latest == nil || v.GreaterThan(latest) {
			latest = v
		}
	}
	if latest == nil {
		return nil, nil, nil
	}

	fixes, predicted, err := b.chainFixesVuln(parent, latest.Original(), chain, fixed)
	if err != nil {
		return nil, nil, err
	}
	if !fixes {
		return nil, nil, nil
	}
	return latest, predicted, nil
}

// chainFixesVuln walks chain forward from parent@version, picking the
// lowest satisfying version at each hop, and reports whether the final
// resolved version of the vuln package lies inside the fixed range.
//
// We are strict about confirmation: the walk must reach the final
// hop (the vuln package) AND that resolved version must be in fixed.
// If any intermediate hop's parent stops declaring the next package
// in the chain, we DO NOT treat that as a fix — the vuln may still be
// transitively reachable via a different chain we don't follow. Such
// cases fall through to override, which is always safe.
//
// Picking lowest at each hop is conservative: if the lowest-allowable
// resolution is fixed, every actual resolution must also be fixed.
// False negatives (pnpm would pick a fixed version but we pessimistically
// pick a vulnerable one) also fall through to override.
func (b *Builder) chainFixesVuln(
	pkg, version string,
	chain []string,
	fixed *semver.Constraints,
) (fixes bool, predicted *semver.Version, err error) {
	if len(chain) == 0 {
		return false, nil, nil
	}
	for i, next := range chain {
		m, err := b.Registry.Manifest(pkg, version)
		if err != nil {
			return false, nil, err
		}
		declared, ok := m.Dependencies[next]
		if !ok {
			// Chain broken at this hop. We cannot confirm the vuln is
			// no longer reachable without walking the full transitive
			// tree, which we don't do. Be conservative.
			return false, nil, nil
		}
		c, err := semver.NewConstraint(declared)
		if err != nil {
			return false, nil, nil
		}
		nextVersions, err := b.Registry.Versions(next)
		if err != nil {
			return false, nil, err
		}
		chosen := lowestSatisfying(nextVersions, c)
		if chosen == nil {
			return false, nil, nil
		}
		if i == len(chain)-1 {
			return fixed.Check(chosen), chosen, nil
		}
		pkg = next
		version = chosen.Original()
	}
	return false, nil, nil
}

// lowestSatisfying returns the lowest non-prerelease version in
// versions that satisfies c, or nil if none qualifies.
func lowestSatisfying(versions []string, c *semver.Constraints) *semver.Version {
	var pool []*semver.Version
	for _, raw := range versions {
		v, err := semver.NewVersion(raw)
		if err != nil {
			continue
		}
		if v.Prerelease() != "" {
			continue
		}
		if !c.Check(v) {
			continue
		}
		pool = append(pool, v)
	}
	if len(pool) == 0 {
		return nil
	}
	for i := 0; i < len(pool); i++ {
		for j := i + 1; j < len(pool); j++ {
			if pool[j].LessThan(pool[i]) {
				pool[i], pool[j] = pool[j], pool[i]
			}
		}
	}
	return pool[0]
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
