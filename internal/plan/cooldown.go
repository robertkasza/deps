package plan

import (
	"fmt"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// DeclaredEdge is one (importer → vulnerable package) edge in the
// resolved tree, paired with the range that importer originally
// declared for the vulnerable package.
//
// For workspace-direct edges, DeclaredRange comes from the workspace's
// package.json (also recorded in pnpm-lock.yaml's importers.specifier
// field). For transitive edges, DeclaredRange comes from the npm
// registry manifest of the importing package — see internal/registry/.
type DeclaredEdge struct {
	// Source is a human-readable identifier for the importer, used
	// only in failure messages (e.g., "apps/admin" or "request@2.88.2").
	Source string
	// DeclaredRange is the npm semver range the importer declared for
	// the vulnerable package (e.g., "^2.4.0", "2.5.0", "workspace:*").
	DeclaredRange string
}

// CanBypassCooldown reports whether adding the patched version to
// minimumReleaseAgeExclude would actually let pnpm resolve it across
// every edge currently pulling in the vulnerable version. The bypass
// works only if every importer's declared range already permits the
// patched version — one exact pin to an older version anywhere in
// the graph kills the approach.
//
// Returns (true, "") if the bypass is viable, or (false, reason)
// describing the first edge that blocks it.
//
// Behavior on edge cases:
//   - No edges → returns (false, "no importers"). The caller almost
//     certainly has a bug; emitting an exclude with nothing in the
//     tree would be pointless.
//   - workspace: protocol specifiers → treated as compatible (they
//     resolve to local workspace links, not registry versions, and
//     the cooldown filter doesn't apply to them).
//   - Unparseable range or version → returns (false, reason). Be
//     conservative: if we can't prove compatibility, fall through
//     to override.
func CanBypassCooldown(edges []DeclaredEdge, patchedVersion string) (bool, string) {
	if len(edges) == 0 {
		return false, "no importers"
	}
	target, err := semver.NewVersion(patchedVersion)
	if err != nil {
		return false, fmt.Sprintf("invalid patched version %q: %v", patchedVersion, err)
	}
	for _, e := range edges {
		r := strings.TrimSpace(e.DeclaredRange)
		if r == "" {
			return false, fmt.Sprintf("%s: declared range is empty", e.Source)
		}
		if strings.HasPrefix(r, "workspace:") {
			continue
		}
		c, err := semver.NewConstraint(r)
		if err != nil {
			return false, fmt.Sprintf("%s: cannot parse range %q: %v", e.Source, r, err)
		}
		if !c.Check(target) {
			return false, fmt.Sprintf("%s: range %q does not permit %s", e.Source, r, patchedVersion)
		}
	}
	return true, ""
}
