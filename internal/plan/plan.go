// Package plan walks the SKILL.md remediation ladder over triaged
// findings and produces a Plan: actionable Edits + unresolved findings.
//
// Plan operates on package-manager-agnostic types from internal/pkgmgr
// and consults internal/registry for parent-bump candidate version data.
package plan

import "github.com/robertkasza/deps/internal/pkgmgr"

// Build produces a Plan from triaged findings.
//
// TODO: implement the ladder:
//   - direct (same major)        -> EditBumpDirect
//   - direct (major jump)         -> Unresolved{major-jump-required}
//   - transitive parent has fix   -> EditBumpParent
//   - transitive parent only major-fix -> Unresolved{major-jump-required}
//   - transitive no parent fix    -> EditOverrideAdd / EditOverrideConsolidate
//   - no fix published            -> Unresolved{no-fix-available}
func Build(findings []pkgmgr.Finding) (pkgmgr.Plan, error) {
	return pkgmgr.Plan{}, nil
}
