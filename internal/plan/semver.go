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

// caretMajor returns the (high, low) pair that npm's `^` operator
// treats as the incompatible-bump boundary. For 1.x and above, only
// the major segment matters: `^1.2.3` accepts any `1.x.y`. For 0.x.y,
// npm caret is stricter — `^0.24.0` accepts only `0.24.x`, so a minor
// bump (0.24 -> 0.25) is the incompatible boundary.
//
// Comparing two versions on this pair answers "are these in the same
// caret-compatibility band?" — which is what the planner needs when
// deciding bump-direct vs major-jump-required.
func caretMajor(v *semver.Version) (uint64, uint64) {
	if v.Major() == 0 {
		return 0, v.Minor()
	}
	return v.Major(), 0
}

// caretMajorGreater reports whether v's caret-major band is strictly
// above anchor's. Compares lexicographically on the (high, low) pair.
func caretMajorGreater(v, anchor *semver.Version) bool {
	vh, vl := caretMajor(v)
	ah, al := caretMajor(anchor)
	if vh != ah {
		return vh > ah
	}
	return vl > al
}

// pickSmallest returns the smallest version in versions that:
//   - satisfies fixed (the advisory's patched_versions range),
//   - shares its caret-major band with anchor (the workspace's current pin),
//   - is strictly greater than anchor.
//
// Returns (nil, false) if none qualifies.
func pickSmallest(versions []string, fixed *semver.Constraints, anchor *semver.Version) (*semver.Version, bool) {
	anchorH, anchorL := caretMajor(anchor)
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
		vh, vl := caretMajor(v)
		if vh != anchorH || vl != anchorL {
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
// fixed AND lives in a caret-major band strictly above anchor's.
// Indicates "fix exists but only across an incompatible boundary" —
// used to distinguish major-jump-required from no-fix-available.
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
		if caretMajorGreater(v, anchor) {
			return true
		}
	}
	return false
}
