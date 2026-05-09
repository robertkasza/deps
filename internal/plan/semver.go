package plan

import (
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// constraintOperator returns the leading operator of a constraint
// string ("^", "~", ">=", ">", "<=", "<", "=", or "" for an exact pin).
// Whitespace is trimmed before inspection.
func constraintOperator(constraint string) string {
	c := strings.TrimSpace(constraint)
	switch {
	case strings.HasPrefix(c, "^"):
		return "^"
	case strings.HasPrefix(c, "~"):
		return "~"
	case strings.HasPrefix(c, ">="):
		return ">="
	case strings.HasPrefix(c, "<="):
		return "<="
	case strings.HasPrefix(c, ">"):
		return ">"
	case strings.HasPrefix(c, "<"):
		return "<"
	case strings.HasPrefix(c, "="):
		return "="
	}
	return ""
}

// applyOperator returns a constraint string by prefixing op to the
// version. An empty op means an exact pin.
func applyOperator(op string, v *semver.Version) string {
	return op + v.Original()
}

// extractAnchor returns the version embedded in a single-version
// constraint (e.g., "^4.17.20" -> 4.17.20). Returns nil if the
// constraint is compound or unparseable.
func extractAnchor(constraint string) *semver.Version {
	c := strings.TrimSpace(constraint)
	c = strings.TrimPrefix(c, constraintOperator(c))
	c = strings.TrimSpace(c)
	if strings.ContainsAny(c, " |&") {
		return nil // compound or wildcard, can't anchor cleanly
	}
	v, err := semver.NewVersion(c)
	if err != nil {
		return nil
	}
	return v
}

// pickSmallest returns the smallest version in versions that:
//   - satisfies fixed (the advisory's patched_versions range),
//   - shares its major with anchor (the workspace's current pin),
//   - is strictly greater than anchor.
//
// Returns (nil, false) if none qualifies.
func pickSmallest(versions []string, fixed *semver.Constraints, anchor *semver.Version) (*semver.Version, bool) {
	var candidates []*semver.Version
	for _, raw := range versions {
		v, err := semver.NewVersion(raw)
		if err != nil {
			continue
		}
		if v.Prerelease() != "" {
			continue
		}
		if !fixed.Check(v) {
			continue
		}
		if v.Major() != anchor.Major() {
			continue
		}
		if !v.GreaterThan(anchor) {
			continue
		}
		candidates = append(candidates, v)
	}
	if len(candidates) == 0 {
		return nil, false
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].LessThan(candidates[j]) })
	return candidates[0], true
}

// hasMajorBumpFix returns true if any version in versions satisfies
// fixed AND has a major number greater than anchor's major. Indicates
// "fix exists but only in a new major" — used to distinguish
// major-jump-required from no-fix-available.
func hasMajorBumpFix(versions []string, fixed *semver.Constraints, anchor *semver.Version) bool {
	for _, raw := range versions {
		v, err := semver.NewVersion(raw)
		if err != nil {
			continue
		}
		if v.Prerelease() != "" {
			continue
		}
		if !fixed.Check(v) {
			continue
		}
		if v.Major() > anchor.Major() {
			return true
		}
	}
	return false
}
