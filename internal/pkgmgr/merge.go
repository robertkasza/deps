package pkgmgr

import (
	"strings"

	"github.com/Masterminds/semver/v3"
)

// MergeOverrides collapses multiple EditOverrideAdd entries that target
// the same (File, Package) into one. Multiple advisories on the same
// vuln package each emit their own override edit; the merged entry uses
// the broadest VulnerableRange (so the override key matches every
// vulnerable version) and the highest To (so the pinned version clears
// every advisory).
//
// It also collapses repeated EditExcludeFromCooldown entries that
// target the same (File, Package, To) — these can be emitted once per
// transitive parent that pulls in the same vuln, and the de-duped
// result is what gets written to pnpm-workspace.yaml anyway.
//
// Called twice in the pipeline: once inside plan.Build to merge
// overrides emitted within a single workspace's plan, and once at
// flatten time across workspaces (overrides land in the monorepo root,
// so multiple workspaces converging on the same vuln pkg must collapse
// to one entry on disk).
//
// Reason strings are concatenated so the merged entry still names every
// GHSA it covers. Non-mergeable edits pass through untouched.
func MergeOverrides(edits []Edit) []Edit {
	type key struct{ file, pkg, to string }
	idx := map[key]int{}
	out := make([]Edit, 0, len(edits))
	for _, e := range edits {
		switch e.Kind {
		case EditOverrideAdd:
			k := key{e.File, e.Package, ""}
			if i, ok := idx[k]; ok {
				out[i] = mergeOverridePair(out[i], e)
				continue
			}
			idx[k] = len(out)
			out = append(out, e)
		case EditExcludeFromCooldown:
			k := key{e.File, e.Package, e.To}
			if i, ok := idx[k]; ok {
				out[i] = mergeCooldownPair(out[i], e)
				continue
			}
			idx[k] = len(out)
			out = append(out, e)
		default:
			out = append(out, e)
		}
	}
	return out
}

func mergeCooldownPair(a, b Edit) Edit {
	if b.Reason != "" && !strings.Contains(a.Reason, b.Reason) {
		a.Reason = a.Reason + "; " + b.Reason
	}
	if a.RejectionNotes == "" {
		a.RejectionNotes = b.RejectionNotes
	}
	return a
}

func mergeOverridePair(a, b Edit) Edit {
	if broaderVulnRange(a.VulnerableRange, b.VulnerableRange) == b.VulnerableRange {
		a.VulnerableRange = b.VulnerableRange
	}
	if higherFixedTarget(a.To, b.To) == b.To {
		a.To = b.To
	}
	if b.Reason != "" && !strings.Contains(a.Reason, b.Reason) {
		a.Reason = a.Reason + "; " + b.Reason
	}
	// RejectionNotes are per-source-finding context that would be
	// near-duplicated across merged overrides (the rejection story
	// is essentially the same for every parent pulling in the same
	// vuln pkg). Keep the first non-empty value rather than
	// concatenating, to avoid 12x bloat when many parents converge.
	if a.RejectionNotes == "" {
		a.RejectionNotes = b.RejectionNotes
	}
	return a
}

// broaderVulnRange picks whichever range covers more vulnerable versions.
// "<3.1.2" is broader than "<3.1.1". Falls back to a on parse failure.
func broaderVulnRange(a, b string) string {
	av, bv := versionInConstraint(a), versionInConstraint(b)
	if av == nil {
		return b
	}
	if bv == nil {
		return a
	}
	if bv.GreaterThan(av) {
		return b
	}
	return a
}

// higherFixedTarget picks whichever override target version is higher.
// ">=3.1.2" beats ">=3.1.1".
func higherFixedTarget(a, b string) string {
	av, bv := versionInConstraint(a), versionInConstraint(b)
	if av == nil && bv == nil {
		return a
	}
	if av == nil {
		return b
	}
	if bv == nil {
		return a
	}
	if bv.GreaterThan(av) {
		return b
	}
	return a
}

func versionInConstraint(s string) *semver.Version {
	t := s
	for _, p := range []string{">=", "<=", "^", "~", ">", "<", "="} {
		if strings.HasPrefix(t, p) {
			t = t[len(p):]
			break
		}
	}
	v, err := semver.NewVersion(t)
	if err != nil {
		return nil
	}
	return v
}
