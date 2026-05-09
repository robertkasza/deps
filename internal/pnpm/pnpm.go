// Package pnpm implements pkgmgr.PkgManager for pnpm-managed projects.
//
// Workspace discovery reads pnpm-workspace.yaml. Audit shells out to
// `pnpm audit --json` per workspace. Edits include both bumping
// dependency constraints in workspace package.json files and writing
// pnpm.overrides into the root package.json.
package pnpm

// Adapter implements pkgmgr.PkgManager for pnpm.
type Adapter struct {
	// runner executes external commands. Override in tests to avoid
	// shelling out to a real `pnpm` binary.
	runner Runner
}

// New returns a pnpm adapter.
func New() *Adapter { return &Adapter{} }

// WithRunner returns a copy of a using the given Runner. Used by tests.
func (a *Adapter) WithRunner(r Runner) *Adapter {
	cp := *a
	cp.runner = r
	return &cp
}

func (a *Adapter) Name() string { return "pnpm" }

