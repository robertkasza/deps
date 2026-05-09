package pnpm

import (
	"fmt"
	"path/filepath"

	"github.com/Masterminds/semver/v3"

	"github.com/robertkasza/deps/internal/pkgmgr"
)

// ApplyEdits writes a slice of edits to disk. Edits are coalesced
// per (file, package) — when multiple edits target the same dependency,
// the highest "To" version wins (covers all advisories with one bump).
//
// Override edits are routed by writeOverride to the appropriate
// pnpm-workspace.yaml or root package.json based on existing config.
//
// On the first error, ApplyEdits returns. Earlier successful writes
// stay on disk; the caller is expected to surface the error and let
// the user decide whether to retry or restore.
func (a *Adapter) ApplyEdits(edits []pkgmgr.Edit) error {
	bumps, overrides, err := groupAndCoalesce(edits)
	if err != nil {
		return err
	}
	for _, b := range bumps {
		if err := writeBump(b.File, b.Field, b.Package, b.To); err != nil {
			return fmt.Errorf("apply bump %s: %w", b.Package, err)
		}
	}
	for _, o := range overrides {
		root := filepath.Dir(o.File)
		if _, err := writeOverride(root, o.Package, o.VulnerableRange, o.To); err != nil {
			return fmt.Errorf("apply override %s: %w", o.Package, err)
		}
	}
	return nil
}

// groupAndCoalesce splits edits into bumps and overrides, dedupes
// (file, package) bumps by picking the highest target version, and
// dedupes (root, package, vulnRange) overrides identically.
func groupAndCoalesce(edits []pkgmgr.Edit) (bumps, overrides []pkgmgr.Edit, err error) {
	bumpByKey := map[string]pkgmgr.Edit{}
	overrideByKey := map[string]pkgmgr.Edit{}

	for _, e := range edits {
		switch e.Kind {
		case pkgmgr.EditBumpDirect, pkgmgr.EditBumpParent:
			key := e.File + "\x00" + e.Package
			cur, ok := bumpByKey[key]
			if !ok {
				bumpByKey[key] = e
				continue
			}
			win, err := higherTarget(cur.To, e.To)
			if err != nil {
				return nil, nil, err
			}
			if win == e.To {
				bumpByKey[key] = e
			}
		case pkgmgr.EditOverrideAdd, pkgmgr.EditOverrideConsolidate:
			key := e.File + "\x00" + e.Package + "\x00" + e.VulnerableRange
			cur, ok := overrideByKey[key]
			if !ok {
				overrideByKey[key] = e
				continue
			}
			// Same vulnerable range, different fixed range: keep the higher one.
			win, err := higherTarget(cur.To, e.To)
			if err != nil {
				return nil, nil, err
			}
			if win == e.To {
				overrideByKey[key] = e
			}
		default:
			return nil, nil, fmt.Errorf("unknown edit kind %q", e.Kind)
		}
	}
	for _, b := range bumpByKey {
		bumps = append(bumps, b)
	}
	for _, o := range overrideByKey {
		overrides = append(overrides, o)
	}
	return bumps, overrides, nil
}

// higherTarget returns whichever of a,b represents a higher version
// constraint (used by the coalescer). Both inputs are constraint
// strings like "^4.17.21" or ">=4.17.21". The version embedded in
// each is compared; the constraint string for the larger version is
// returned.
func higherTarget(a, b string) (string, error) {
	av := versionInConstraint(a)
	bv := versionInConstraint(b)
	if av == nil && bv == nil {
		return a, nil
	}
	if av == nil {
		return b, nil
	}
	if bv == nil {
		return a, nil
	}
	if bv.GreaterThan(av) {
		return b, nil
	}
	return a, nil
}

// versionInConstraint returns the embedded version of a single-version
// constraint ("^4.17.21" -> 4.17.21). Returns nil for compound or
// unparseable constraints.
func versionInConstraint(s string) *semver.Version {
	t := s
	for _, p := range []string{"^", "~", ">=", "<=", ">", "<", "="} {
		if len(t) >= len(p) && t[:len(p)] == p {
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
