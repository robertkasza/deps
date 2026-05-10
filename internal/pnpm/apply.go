package pnpm

import (
	"fmt"
	"path/filepath"

	"github.com/robertkasza/deps/internal/pkgmgr"
)

// ApplyEdits writes each edit to disk in order and returns the edits
// that were applied. Override edits are routed by writeOverride to the
// appropriate pnpm-workspace.yaml or root package.json based on
// existing config.
//
// The planner is responsible for emitting one edit per
// (file, package); ApplyEdits does no grouping or merging. On the
// first write error, ApplyEdits returns whatever it managed to apply
// so far along with the error — earlier successful writes stay on
// disk.
func (a *Adapter) ApplyEdits(edits []pkgmgr.Edit) ([]pkgmgr.Edit, error) {
	applied := make([]pkgmgr.Edit, 0, len(edits))
	for _, e := range edits {
		switch e.Kind {
		case pkgmgr.EditBumpDirect, pkgmgr.EditBumpParent:
			if err := writeBump(e.File, e.Field, e.Package, e.To); err != nil {
				return applied, fmt.Errorf("apply bump %s: %w", e.Package, err)
			}
		case pkgmgr.EditOverrideAdd, pkgmgr.EditOverrideConsolidate:
			root := filepath.Dir(e.File)
			if _, err := writeOverride(root, e.Package, e.VulnerableRange, e.To); err != nil {
				return applied, fmt.Errorf("apply override %s: %w", e.Package, err)
			}
		default:
			return applied, fmt.Errorf("unknown edit kind %q", e.Kind)
		}
		applied = append(applied, e)
	}
	return applied, nil
}
