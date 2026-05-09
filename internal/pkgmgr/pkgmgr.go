// Package pkgmgr defines the adapter interface deps uses to interact
// with a package manager (pnpm today; npm/yarn are future seams).
//
// The CLI auto-detects which adapter to use based on lockfile presence
// at the monorepo root.
package pkgmgr

// PkgManager abstracts the package-manager-specific operations deps
// performs. Everything package-manager-agnostic (triage, plan, registry,
// report) is consumer of this interface, not implementer.
type PkgManager interface {
	// Name returns a stable identifier ("pnpm", "npm", ...).
	Name() string

	// DiscoverWorkspaces returns all workspaces in the monorepo rooted
	// at root. For a single-package repo, returns one synthetic workspace.
	DiscoverWorkspaces(root string) ([]Workspace, error)

	// Audit runs the package manager's audit against a single workspace
	// and returns advisories attributed to it.
	Audit(ws Workspace) ([]Advisory, error)

	// ApplyEdits writes Edits to disk. Implementations preserve formatting
	// of existing package.json files. Returns the edits that were
	// actually applied — typically fewer than the input because edits
	// targeting the same package or override key are coalesced.
	ApplyEdits(edits []Edit) ([]Edit, error)

	// Install regenerates the lockfile after edits. lockfileOnly == true
	// skips populating node_modules.
	Install(root string, lockfileOnly bool) error
}

// Detect returns the appropriate PkgManager for a directory by looking
// for lockfiles (pnpm-lock.yaml -> pnpm, package-lock.json -> npm, etc.).
//
// TODO: implement once the pnpm adapter exists.
func Detect(root string) (PkgManager, error) {
	return nil, nil
}
