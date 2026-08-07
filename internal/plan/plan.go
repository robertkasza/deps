// Package plan walks the SKILL.md remediation ladder over triaged
// findings and produces a Plan: actionable Edits + unresolved findings.
//
// Findings are grouped before the ladder runs. Direct findings group
// by (workspace, package); transitive findings group by (workspace,
// parent, vuln pkg). Within each group, advisories are decided
// individually so that a parent bump can fix some advisories while
// override picks up the rest — overrides are sticky tech debt and we
// never use one when a parent bump would do.
//
// The ladder, per advisory within a group:
//
//	Direct:
//	  1. fix in same major as current pin                  -> bump-direct (one bump per group covering all same-major-fixable advisories)
//	  2. only major-bump fixes                             -> unresolved{major-jump-required}
//	  3. no fix published                                  -> unresolved{no-fix-available}
//
//	Transitive:
//	  1. latest same-major parent resolves vuln to a fixed version -> bump-parent (one bump per group covering all advisories it patches)
//	  2. only newer-major parent resolves to a fixed version       -> unresolved{major-jump-required}
//	  3. no parent version resolves to a fixed version             -> override-add (merged across the workspace's vuln pkg)
//	  4. no patched version of vuln pkg published anywhere         -> unresolved{no-fix-available}
//
// Plan operates on package-manager-agnostic types from internal/pkgmgr
// and consults internal/registry for parent-bump candidate version data.
package plan

import (
	"fmt"
	"path/filepath"
	"strings"

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

// TreeInspector enumerates importers of a vulnerable package in the
// resolved tree of a specific workspace. Pnpm monorepos using
// sharedWorkspaceLockfile=false have one lockfile per workspace, so
// the lookup must be scoped per workspace, not global.
//
// nil means the cooldown-bypass rung is unavailable and plan should
// skip it.
type TreeInspector interface {
	// ImportersOfRange returns every direct-dep edge in the
	// workspace's resolved tree where pkg is pulled in at a version
	// satisfying vulnRange (e.g., advisory VulnerableRange "<2.5.1").
	ImportersOfRange(ws pkgmgr.Workspace, pkg, vulnRange string) []pkgmgr.ImporterEdge
}

// Builder produces Plans from triaged findings.
type Builder struct {
	Registry registry.Client
	// Tree is consulted to decide cooldown-bypass viability. nil
	// disables the cooldown rung (override is used directly when the
	// parent-bump path doesn't apply).
	Tree TreeInspector
	// CooldownActive indicates that pnpm will currently apply the
	// minimumReleaseAge filter in this repo. When false, the cooldown
	// rung is skipped because an exclude entry would be useless.
	CooldownActive bool
	// AllowMajor lets the cooldown-bypass rung lift the cooldown for a
	// patched version even when an importer's declared range doesn't
	// permit it (typically a major jump on paper). Off by default; the
	// user opts in via --allow-major when an override has already
	// drifted the package's effective resolution past the declared
	// range. See CanBypassCooldown.
	AllowMajor bool
}

// New returns a Builder using the given registry client.
func New(reg registry.Client) *Builder { return &Builder{Registry: reg} }

// Build walks the remediation ladder for each finding.
//
// Direct findings are grouped by (workspace, package) before planning
// so that multiple advisories on the same direct dep collapse into one
// bump-direct edit whose target version satisfies every advisory's
// FixedRange. Transitive findings are still walked individually here;
// override-add edits are merged at the end.
func (b *Builder) Build(findings []pkgmgr.Finding) (pkgmgr.Plan, error) {
	cache := manifestCache{}
	plan := pkgmgr.Plan{}

	type dkey struct{ file, pkg string }
	directGroups := map[dkey][]pkgmgr.Finding{}
	var directOrder []dkey
	var transitive []pkgmgr.Finding

	// The same advisory surfaces once per dependency path, so a single
	// vuln can yield dozens of identical findings within a group. Collapse
	// those to one per advisory: keeping the duplicates produces repeated
	// output lines and, worse, overflows the intersected-constraint string
	// past Masterminds/semver's 512-byte limit when a package is reached
	// via many paths.
	seenDirect := map[dkey]map[string]bool{}

	for _, f := range findings {
		switch f.Kind {
		case pkgmgr.FindingDirect:
			k := dkey{f.Advisory.Workspace.PackageJSON, f.Advisory.Package}
			if _, exists := directGroups[k]; !exists {
				directOrder = append(directOrder, k)
				seenDirect[k] = map[string]bool{}
			}
			id := advisoryID(f.Advisory)
			if seenDirect[k][id] {
				continue
			}
			seenDirect[k][id] = true
			directGroups[k] = append(directGroups[k], f)
		case pkgmgr.FindingTransitive:
			transitive = append(transitive, f)
		default:
			return plan, fmt.Errorf("unknown finding kind %q", f.Kind)
		}
	}

	for _, k := range directOrder {
		edit, unresolved, err := b.planDirectGroup(directGroups[k], cache)
		if err != nil {
			return plan, err
		}
		if edit != nil {
			plan.Actionable = append(plan.Actionable, *edit)
		}
		plan.Unresolved = append(plan.Unresolved, unresolved...)
	}

	type tkey struct{ file, parent, vuln string }
	transitiveGroups := map[tkey][]pkgmgr.Finding{}
	var transitiveOrder []tkey
	seenTransitive := map[tkey]map[string]bool{}
	for _, f := range transitive {
		k := tkey{f.Advisory.Workspace.PackageJSON, f.Parent, f.Advisory.Package}
		if _, exists := transitiveGroups[k]; !exists {
			transitiveOrder = append(transitiveOrder, k)
			seenTransitive[k] = map[string]bool{}
		}
		id := advisoryID(f.Advisory)
		if seenTransitive[k][id] {
			continue
		}
		seenTransitive[k][id] = true
		transitiveGroups[k] = append(transitiveGroups[k], f)
	}
	for _, k := range transitiveOrder {
		edits, unresolved, err := b.planTransitiveGroup(transitiveGroups[k], cache)
		if err != nil {
			return plan, err
		}
		plan.Actionable = append(plan.Actionable, edits...)
		plan.Unresolved = append(plan.Unresolved, unresolved...)
	}

	plan.Actionable = pkgmgr.MergeOverrides(plan.Actionable)
	return plan, nil
}

// advisoryID returns a stable identity for an advisory, used to collapse
// the duplicate findings the same advisory produces across dependency
// paths. The vulnerable/fixed range pair is part of the key, not just the
// GHSA: a single GHSA can cover several major lines of the same package
// (e.g. ws's GHSA-96hv-2xvq-fx4p patches 6.2.4, 7.5.11 and 8.21.0
// separately), surfacing as distinct records with different ranges. Those
// are NOT duplicates — each needs its own remediation — so keying on GHSA
// alone would wrongly drop all but one line. True per-path duplicates
// share the GHSA and both ranges, so they still collapse.
func advisoryID(a pkgmgr.Advisory) string {
	return a.GHSA + "|" + a.VulnerableRange + "|" + a.FixedRange
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

// planDirectGroup plans one bump-direct edit covering every advisory
// in a (workspace, package) group. The bump's target version must
// satisfy the intersection of all advisories' FixedRange constraints.
//
// Advisories that have no published fix, or whose fix only exists in a
// higher major than the workspace's pin, are returned individually as
// Unresolved; they cannot be cleared by the same-major bump and don't
// participate in the intersection.
func (b *Builder) planDirectGroup(group []pkgmgr.Finding, cache manifestCache) (*pkgmgr.Edit, []pkgmgr.Unresolved, error) {
	pkg := group[0].Advisory.Package
	ws := group[0].Advisory.Workspace

	var unresolved []pkgmgr.Unresolved
	var withFix []pkgmgr.Finding

	for _, f := range group {
		if isNoFix(f.Advisory.FixedRange) {
			unresolved = append(unresolved, pkgmgr.Unresolved{Finding: f, Reason: ReasonNoFixAvailable})
			continue
		}
		withFix = append(withFix, f)
	}
	if len(withFix) == 0 {
		return nil, unresolved, nil
	}

	manifest, err := cache.get(ws)
	if err != nil {
		return nil, nil, err
	}

	current, field, ok := manifest.findDep(pkg)
	if !ok {
		// triage thought these were direct but the manifest doesn't list them.
		for _, f := range withFix {
			unresolved = append(unresolved, pkgmgr.Unresolved{Finding: f, Reason: ReasonParentNotInDeps})
		}
		return nil, unresolved, nil
	}

	op := constraintOperator(current)
	anchor := extractAnchor(current)
	if anchor == nil {
		return nil, nil, fmt.Errorf("cannot parse current constraint %q for %s", current, pkg)
	}

	versions, err := b.Registry.Versions(pkg)
	if err != nil {
		return nil, nil, fmt.Errorf("registry %s: %w", pkg, err)
	}

	// Partition withFix by whether each advisory has a same-major fix.
	// Advisories that only have a newer-major fix can't be cleared by
	// a same-major bump; mark them unresolved and exclude from the
	// intersection so they don't poison the bump for the others.
	var sameMajor []pkgmgr.Finding
	for _, f := range withFix {
		fixed, err := semver.NewConstraint(f.Advisory.FixedRange)
		if err != nil {
			return nil, nil, fmt.Errorf("parse fixed range %q for %s: %w", f.Advisory.FixedRange, pkg, err)
		}
		if _, ok := pickSmallest(versions, fixed, anchor); ok {
			sameMajor = append(sameMajor, f)
			continue
		}
		if hasMajorBumpFix(versions, fixed, anchor) {
			unresolved = append(unresolved, pkgmgr.Unresolved{Finding: f, Reason: ReasonMajorJumpRequired})
		} else {
			unresolved = append(unresolved, pkgmgr.Unresolved{Finding: f, Reason: ReasonNoFixAvailable})
		}
	}
	if len(sameMajor) == 0 {
		return nil, unresolved, nil
	}

	merged, err := intersectFixedRanges(sameMajor)
	if err != nil {
		return nil, nil, fmt.Errorf("intersect fixed ranges for %s: %w", pkg, err)
	}

	target, ok := pickSmallest(versions, merged, anchor)
	if !ok {
		// The advisories are individually fixable in same-major but no
		// single same-major version satisfies all of them at once
		// (rare: e.g. "<3.5.0" patched_versions on one and ">=3.5.0" on
		// another). Treat as major-jump-required for the whole group.
		for _, f := range sameMajor {
			unresolved = append(unresolved, pkgmgr.Unresolved{Finding: f, Reason: ReasonMajorJumpRequired})
		}
		return nil, unresolved, nil
	}

	edit := &pkgmgr.Edit{
		Kind:    pkgmgr.EditBumpDirect,
		File:    ws.PackageJSON,
		Package: pkg,
		Field:   string(field),
		From:    current,
		To:      applyOperator(op, target),
		Reason:  groupBumpReason(sameMajor),
	}
	return edit, unresolved, nil
}

// intersectFixedRanges returns a constraint that holds iff every
// advisory's FixedRange holds. Built by joining the individual
// constraint strings with commas (Masterminds/semver treats
// space/comma-separated subexpressions as AND).
func intersectFixedRanges(findings []pkgmgr.Finding) (*semver.Constraints, error) {
	parts := make([]string, 0, len(findings))
	for _, f := range findings {
		parts = append(parts, f.Advisory.FixedRange)
	}
	return semver.NewConstraint(strings.Join(parts, ", "))
}

// groupBumpReason summarises which advisories a grouped bump fixes.
func groupBumpReason(findings []pkgmgr.Finding) string {
	if len(findings) == 1 {
		f := findings[0]
		return fmt.Sprintf("fixes %s (%s)", f.Advisory.GHSA, f.Advisory.Package)
	}
	ghsa := make([]string, 0, len(findings))
	for _, f := range findings {
		ghsa = append(ghsa, f.Advisory.GHSA)
	}
	return fmt.Sprintf("fixes %s (%s)", strings.Join(ghsa, ", "), findings[0].Advisory.Package)
}

// planTransitiveGroup plans remediation for all transitive findings
// sharing (workspace, parent, vuln pkg). Each advisory is decided
// individually within the group, per the project policy that overrides
// are sticky tech debt: prefer a parent bump for any advisory it can
// fix, and fall to override only for advisories the parent bump leaves
// vulnerable.
//
// Returns the edits to add to the plan plus per-advisory unresolved
// entries.
func (b *Builder) planTransitiveGroup(group []pkgmgr.Finding, cache manifestCache) ([]pkgmgr.Edit, []pkgmgr.Unresolved, error) {
	parent := group[0].Parent
	vuln := group[0].Advisory.Package
	ws := group[0].Advisory.Workspace

	var unresolved []pkgmgr.Unresolved
	var withFix []pkgmgr.Finding
	for _, f := range group {
		if isNoFix(f.Advisory.FixedRange) {
			unresolved = append(unresolved, pkgmgr.Unresolved{Finding: f, Reason: ReasonNoFixAvailable})
			continue
		}
		withFix = append(withFix, f)
	}
	if len(withFix) == 0 {
		return nil, unresolved, nil
	}

	manifest, err := cache.get(ws)
	if err != nil {
		return nil, nil, err
	}

	currentParent, field, ok := manifest.findDep(parent)
	if !ok {
		// Parent isn't in this workspace's manifest. Could be a transitive
		// chain longer than 2; fall everything through to override.
		var edits []pkgmgr.Edit
		for _, f := range withFix {
			edits = append(edits, b.planOverride(f))
		}
		return edits, unresolved, nil
	}

	op := constraintOperator(currentParent)
	anchor := extractAnchor(currentParent)
	if anchor == nil {
		return nil, nil, fmt.Errorf("cannot parse parent constraint %q for %s", currentParent, parent)
	}

	versions, err := b.Registry.Versions(parent)
	if err != nil {
		return nil, nil, fmt.Errorf("registry %s: %w", parent, err)
	}

	// chain is the full dep path from parent down to vuln, e.g.
	// [@scalar/openapi-parser, ajv, fast-uri]. The Advisory.Path
	// includes the parent at index 0; chain is everything after.
	chain := withFix[0].Advisory.Path
	if len(chain) > 0 && chain[0] == parent {
		chain = chain[1:]
	}

	// Predict where the vuln package would resolve at the latest
	// same-major and latest newer-major parent versions. Either may
	// be nil (no candidate) or yield a nil predicted vuln (chain
	// broken before reaching vuln).
	sameMajorParent := latestParentInBand(versions, anchor, true)
	var predictedSame *semver.Version
	if sameMajorParent != nil {
		predictedSame, err = b.predictChainResolution(parent, sameMajorParent.Original(), chain)
		if err != nil {
			return nil, nil, err
		}
	}
	newerMajorParent := latestParentInBand(versions, anchor, false)
	var predictedNewer *semver.Version
	if newerMajorParent != nil {
		predictedNewer, err = b.predictChainResolution(parent, newerMajorParent.Original(), chain)
		if err != nil {
			return nil, nil, err
		}
	}

	// parentBumpReason describes why the parent-bump rung didn't pick
	// up a finding that ended up in fallToOverride. Used when annotating
	// the eventual override edit so the user can see what was tried.
	parentBumpReason := parentBumpRejectionReason(parent, vuln, sameMajorParent, predictedSame)

	var fixedBySameMajor []pkgmgr.Finding
	type rejected struct {
		finding pkgmgr.Finding
		why     string
	}
	var fallToOverride []rejected
	for _, f := range withFix {
		fixed, err := semver.NewConstraint(f.Advisory.FixedRange)
		if err != nil {
			return nil, nil, fmt.Errorf("parse fixed range %q for %s: %w", f.Advisory.FixedRange, vuln, err)
		}
		if predictedSame != nil && fixed.Check(predictedSame) {
			fixedBySameMajor = append(fixedBySameMajor, f)
			continue
		}
		if predictedNewer != nil && fixed.Check(predictedNewer) {
			// A same-major parent bump can't carry the fix and only a
			// newer-major parent would pull a fixed version through natural
			// resolution. We don't auto-apply breaking major parent bumps —
			// but the vulnerable package itself only needs a same-major bump,
			// which an override delivers directly without touching the
			// parent. Fall through to the override rung instead of
			// abandoning the finding as major-jump-required (which left
			// trivially-patchable transitive vulns unfixed; `pnpm audit
			// --fix` resolves these via the same override).
			why := fmt.Sprintf("parent-bump would require a major jump: only %s@%s (new major) resolves %s to a fixed version",
				parent, newerMajorParent.Original(), vuln)
			fallToOverride = append(fallToOverride, rejected{f, why})
			continue
		}
		fallToOverride = append(fallToOverride, rejected{f, parentBumpReason})
	}

	var edits []pkgmgr.Edit
	if len(fixedBySameMajor) > 0 {
		edits = append(edits, pkgmgr.Edit{
			Kind:    pkgmgr.EditBumpParent,
			File:    ws.PackageJSON,
			Package: parent,
			Field:   string(field),
			From:    currentParent,
			To:      applyOperator(op, sameMajorParent),
			Reason:  groupParentBumpReason(fixedBySameMajor, vuln, predictedSame),
		})
	}
	for _, r := range fallToOverride {
		e, cdReason := b.tryCooldownBypass(r.finding)
		if cdReason == "" {
			edits = append(edits, e)
			continue
		}
		ov := b.planOverride(r.finding)
		ov.RejectionNotes = composeRejectionNotes(r.why, cdReason)
		edits = append(edits, ov)
	}
	return edits, unresolved, nil
}

// parentBumpRejectionReason explains in one short phrase why the
// parent-bump rung couldn't fix a given transitive advisory. It
// inspects only the same-major candidate; major-jump cases never
// reach the fall-through branch.
func parentBumpRejectionReason(parent, vuln string, sameMajorParent, predictedSame *semver.Version) string {
	switch {
	case sameMajorParent == nil:
		return fmt.Sprintf("parent-bump not viable: no newer same-major %s available", parent)
	case predictedSame == nil:
		return fmt.Sprintf("parent-bump not viable: latest same-major %s@%s no longer reaches %s in its dep chain",
			parent, sameMajorParent.Original(), vuln)
	default:
		return fmt.Sprintf("parent-bump not viable: latest same-major %s@%s still resolves %s@%s (vulnerable)",
			parent, sameMajorParent.Original(), vuln, predictedSame.Original())
	}
}

// composeRejectionNotes assembles a single-line note explaining why
// the parent-bump and cooldown-bypass rungs were rejected for this
// specific finding. Stored on Edit.RejectionNotes (not Reason) so it
// doesn't multiply across merged overrides.
func composeRejectionNotes(parentBumpWhy, cooldownWhy string) string {
	var parts []string
	if parentBumpWhy != "" {
		parts = append(parts, parentBumpWhy)
	}
	if cooldownWhy != "" {
		parts = append(parts, "cooldown-bypass not viable: "+cooldownWhy)
	}
	return strings.Join(parts, "; ")
}

// tryCooldownBypass attempts to remediate a transitive finding by
// adding the lowest fixed version to pnpm-workspace.yaml's
// minimumReleaseAgeExclude list. Viable only when:
//   - the cooldown filter is currently active in this repo
//   - a TreeInspector is configured (we need to enumerate importers)
//   - a concrete patched version exists in the registry that
//     satisfies the advisory's FixedRange
//   - every importer's declared range for the vulnerable package
//     already permits the patched version (so lifting the cooldown
//     is the only change needed to make resolution pick the fix)
//
// Returns (edit, true) when the bypass is viable; (zero, false)
// otherwise so the caller falls through to override.
// tryCooldownBypass returns (edit, "") on success, or
// (zero, reason) explaining why the bypass wasn't viable. The reason
// is suitable for embedding in the override edit's Reason field so
// the user can see why the higher ladder rung was skipped.
func (b *Builder) tryCooldownBypass(f pkgmgr.Finding) (pkgmgr.Edit, string) {
	vuln := f.Advisory.Package
	ghsa := f.Advisory.GHSA
	if !b.CooldownActive {
		return pkgmgr.Edit{}, "minimumReleaseAge not active (set in pnpm-workspace.yaml or pnpm >= 11)"
	}
	if b.Tree == nil {
		return pkgmgr.Edit{}, "lockfile not available"
	}
	fixed, err := semver.NewConstraint(f.Advisory.FixedRange)
	if err != nil {
		return pkgmgr.Edit{}, fmt.Sprintf("unparseable FixedRange %q", f.Advisory.FixedRange)
	}
	versions, err := b.Registry.Versions(vuln)
	if err != nil {
		return pkgmgr.Edit{}, fmt.Sprintf("registry lookup failed: %v", err)
	}
	patched := lowestSatisfying(versions, fixed)
	if patched == nil {
		return pkgmgr.Edit{}, fmt.Sprintf("no published %s version satisfies %q", vuln, f.Advisory.FixedRange)
	}

	rawEdges := b.Tree.ImportersOfRange(f.Advisory.Workspace, vuln, f.Advisory.VulnerableRange)
	if len(rawEdges) == 0 {
		return pkgmgr.Edit{}, fmt.Sprintf("no importers of %s@%s in lockfile", vuln, f.Advisory.VulnerableRange)
	}

	edges, ok := b.resolveDeclaredEdges(rawEdges, vuln)
	if !ok {
		return pkgmgr.Edit{}, "could not resolve declared ranges for all importers"
	}
	if viable, reason := CanBypassCooldown(edges, patched.Original(), b.AllowMajor); !viable {
		return pkgmgr.Edit{}, fmt.Sprintf("patched=%s; %s", patched.Original(), reason)
	}

	reason := fmt.Sprintf("lift install cooldown for transitive %s@%s (%s)",
		vuln, patched.Original(), ghsa)
	// Flag when --allow-major was what carried this past the declared
	// range, so the plan output makes the opt-in visible rather than
	// presenting an out-of-range patch as routine.
	if b.AllowMajor {
		if strict, _ := CanBypassCooldown(edges, patched.Original(), false); !strict {
			reason += " [--allow-major: patched version is outside an importer's declared range]"
		}
	}

	return pkgmgr.Edit{
		Kind:    pkgmgr.EditExcludeFromCooldown,
		File:    filepath.Join(f.Advisory.Workspace.MonorepoRoot, "pnpm-workspace.yaml"),
		Package: vuln,
		To:      patched.Original(),
		Reason:  reason,
	}, ""
}

// resolveDeclaredEdges turns importer edges from the lockfile into
// DeclaredEdges by filling in the declared range for each transitive
// importer (workspace edges already have it from the lockfile).
//
// Returns (edges, false) if any registry lookup fails or any importer
// doesn't list the vulnerable package as a dependency — both indicate
// we can't prove the bypass is safe and should fall through.
func (b *Builder) resolveDeclaredEdges(raw []pkgmgr.ImporterEdge, vuln string) ([]DeclaredEdge, bool) {
	out := make([]DeclaredEdge, 0, len(raw))
	for _, e := range raw {
		if e.IsWorkspace {
			out = append(out, DeclaredEdge{
				Source:        e.ImporterName,
				DeclaredRange: e.DeclaredRange,
			})
			continue
		}
		m, err := b.Registry.Manifest(e.ImporterName, e.ImporterVersion)
		if err != nil {
			return nil, false
		}
		declared, ok := m.Dependencies[vuln]
		if !ok {
			declared = m.PeerDependencies[vuln]
		}
		if declared == "" {
			return nil, false
		}
		out = append(out, DeclaredEdge{
			Source:        e.ImporterName + "@" + e.ImporterVersion,
			DeclaredRange: declared,
		})
	}
	return out, true
}

// latestParentInBand returns the highest non-prerelease parent version
// in the requested major band (same major as anchor, or strictly
// greater). Returns nil if no candidate qualifies.
//
// We only consider the latest version because vuln fixes propagate
// forward in time: once an intermediate package updates its dep range
// to require a fixed vuln version, only later parent releases carry
// the fix. Searching older same-major versions can't surface a fix
// that the latest doesn't already include.
func latestParentInBand(versions []string, anchor *semver.Version, sameMajor bool) *semver.Version {
	var latest *semver.Version
	for _, raw := range versions {
		v, err := semver.NewVersion(raw)
		if err != nil {
			continue
		}
		if v.Prerelease() != "" {
			continue
		}
		if sameMajor {
			vh, vl := caretMajor(v)
			ah, al := caretMajor(anchor)
			if vh != ah || vl != al || !v.GreaterThan(anchor) {
				continue
			}
		} else if !caretMajorGreater(v, anchor) {
			continue
		}
		if latest == nil || v.GreaterThan(latest) {
			latest = v
		}
	}
	return latest
}

// predictChainResolution walks chain forward from parent@version,
// picking the lowest satisfying version at each hop, and returns the
// final resolved version of the last package in chain. Returns nil if
// the chain breaks before reaching the end (an intermediate hop no
// longer declares the next package, or no version satisfies a hop's
// constraint).
//
// Picking lowest at each hop is conservative: if the lowest-allowable
// resolution is fixed, every actual resolution must be too. Callers
// check the returned version against an advisory's fixed range to
// decide whether the bump actually patches that advisory.
func (b *Builder) predictChainResolution(parent, version string, chain []string) (*semver.Version, error) {
	if len(chain) == 0 {
		return nil, nil
	}
	pkg, ver := parent, version
	for i, next := range chain {
		m, err := b.Registry.Manifest(pkg, ver)
		if err != nil {
			return nil, err
		}
		declared, ok := m.Dependencies[next]
		if !ok {
			return nil, nil
		}
		c, err := semver.NewConstraint(declared)
		if err != nil {
			return nil, nil
		}
		nextVersions, err := b.Registry.Versions(next)
		if err != nil {
			return nil, err
		}
		chosen := lowestSatisfying(nextVersions, c)
		if chosen == nil {
			return nil, nil
		}
		if i == len(chain)-1 {
			return chosen, nil
		}
		pkg = next
		ver = chosen.Original()
	}
	return nil, nil
}

// groupParentBumpReason names every advisory a grouped parent bump
// fixes, plus the predicted resolved vuln version.
func groupParentBumpReason(findings []pkgmgr.Finding, vuln string, predicted *semver.Version) string {
	ghsa := make([]string, 0, len(findings))
	for _, f := range findings {
		ghsa = append(ghsa, f.Advisory.GHSA)
	}
	if predicted != nil {
		return fmt.Sprintf("predicted to patch transitive %s (resolves to %s@%s; %s)",
			vuln, vuln, predicted.Original(), strings.Join(ghsa, ", "))
	}
	return fmt.Sprintf("predicted to patch transitive %s (chain no longer reaches it; %s)",
		vuln, strings.Join(ghsa, ", "))
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
			To:              b.overrideTarget(f.Advisory.Package, f.Advisory.FixedRange),
			Reason:          fmt.Sprintf("override transitive %s (%s)", f.Advisory.Package, f.Advisory.GHSA),
		}
	}
	return pkgmgr.Edit{
		Kind:            pkgmgr.EditOverrideAdd,
		File:            filepath.Join(root, "package.json"),
		Package:         f.Advisory.Package,
		VulnerableRange: f.Advisory.VulnerableRange,
		To:              b.overrideTarget(f.Advisory.Package, f.Advisory.FixedRange),
		Reason:          fmt.Sprintf("override transitive %s (%s)", f.Advisory.Package, f.Advisory.GHSA),
	}
}

// overrideTarget builds the version spec for a pnpm override from an
// advisory's patched_versions range. The default is the open-ended
// ">=<min-fixed>" that `pnpm audit --fix` emits, which resolves to the
// highest published version satisfying it.
//
// It appends a caret ceiling ONLY when the registry publishes a version
// above the fix's caret band (a higher major for 1.x+, a higher minor
// for 0.x). That is the exact condition under which the open-ended form
// would let pnpm resolve the override across a breaking boundary and
// drag unrelated importers onto a new major (e.g. js-yaml 4 -> 5).
// Whenever no such version exists, the capped and open-ended forms pick
// the same version, so we stay byte-for-byte identical to
// `pnpm audit --fix` everywhere it already works.
//
// Best-effort: if the fixed range is compound/unparseable, returns it
// raw; if the registry lookup fails, returns the open-ended floor.
func (b *Builder) overrideTarget(pkg, fixed string) string {
	v := extractAnchor(fixed)
	if v == nil {
		return fixed
	}
	floor := ">=" + v.Original()
	versions, err := b.Registry.Versions(pkg)
	if err != nil {
		return floor
	}
	if !hasVersionAboveCaret(versions, v) {
		return floor
	}
	return floor + " <" + caretCeiling(v)
}

// hasVersionAboveCaret reports whether any published non-prerelease
// version sits in a caret band strictly above v's. That is the only
// case where an open-ended ">=v" override can resolve across a breaking
// boundary, so it is the only case where a ceiling is needed.
func hasVersionAboveCaret(versions []string, v *semver.Version) bool {
	for _, raw := range versions {
		c, err := semver.NewVersion(raw)
		if err != nil {
			continue
		}
		if c.Prerelease() != "" {
			continue
		}
		if caretMajorGreater(c, v) {
			return true
		}
	}
	return false
}

// caretCeiling returns the exclusive upper bound of v's caret band as a
// version string: the next major for 1.x+, or the next minor for 0.x
// (mirroring npm's stricter caret rules for 0.x; see caretMajor).
func caretCeiling(v *semver.Version) string {
	if v.Major() == 0 {
		return fmt.Sprintf("0.%d.0", v.Minor()+1)
	}
	return fmt.Sprintf("%d.0.0", v.Major()+1)
}
