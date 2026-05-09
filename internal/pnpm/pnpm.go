// Package pnpm implements pkgmgr.PkgManager for pnpm-managed projects.
//
// Workspace discovery reads pnpm-workspace.yaml. Audit shells out to
// `pnpm audit --json` per workspace. Edits include both bumping
// dependency constraints in workspace package.json files and writing
// pnpm.overrides into the root package.json.
package pnpm

import "github.com/robertkasza/deps/internal/pkgmgr"

// Adapter implements pkgmgr.PkgManager for pnpm.
type Adapter struct{}

// New returns a pnpm adapter.
func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string { return "pnpm" }

func (a *Adapter) Audit(ws pkgmgr.Workspace) ([]pkgmgr.Advisory, error) {
	// TODO: run `pnpm audit --json` in ws.Dir, parse, attribute advisories.
	return nil, nil
}

func (a *Adapter) ApplyEdits(edits []pkgmgr.Edit) error {
	// TODO: mutate package.json files, preserving formatting.
	return nil
}

func (a *Adapter) Install(root string, lockfileOnly bool) error {
	// TODO: shell out to `pnpm install` (with --lockfile-only when set).
	return nil
}
