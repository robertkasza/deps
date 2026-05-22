package pnpm

import (
	"path/filepath"
	"sync"

	"github.com/robertkasza/deps/internal/pkgmgr"
)

// WorkspaceLockfiles routes ImportersOfRange queries to the lockfile
// co-located with each workspace.
//
// pnpm monorepos can be configured with sharedWorkspaceLockfile=false
// (per-workspace lockfiles) or =true (one root lockfile). Either way,
// the right lockfile for a finding is the one at
// <workspaceDir>/pnpm-lock.yaml — for the shared mode, every workspace
// dir resolves to the same root path, so caching by path naturally
// collapses to one parse. For the per-workspace mode, each workspace
// dir resolves to its own file.
//
// Lockfiles are parsed lazily on first query and cached. Parse errors
// for one workspace's lockfile don't affect others — that workspace
// just returns zero edges, which is the correct conservative fallback
// (fall through to override).
type WorkspaceLockfiles struct {
	// resolve returns the absolute path of the lockfile to consult
	// for the given workspace. Default is <ws.Dir>/pnpm-lock.yaml.
	resolve func(pkgmgr.Workspace) string

	mu    sync.Mutex
	cache map[string]*Lockfile // absolute path -> parsed lockfile
}

// NewWorkspaceLockfiles returns an empty cache that lazy-parses
// lockfiles on first access.
func NewWorkspaceLockfiles() *WorkspaceLockfiles {
	return &WorkspaceLockfiles{
		resolve: func(ws pkgmgr.Workspace) string {
			return filepath.Join(ws.Dir, "pnpm-lock.yaml")
		},
		cache: map[string]*Lockfile{},
	}
}

// ImportersOfRange satisfies plan.TreeInspector. Returns zero edges
// when the workspace's lockfile is missing or unparseable; callers
// treat that as "rung not viable here" and fall through to override.
func (w *WorkspaceLockfiles) ImportersOfRange(ws pkgmgr.Workspace, pkg, vulnRange string) []pkgmgr.ImporterEdge {
	lf, ok := w.lockfileFor(ws)
	if !ok {
		return nil
	}
	return lf.ImportersOfRange(pkg, vulnRange)
}

// lockfileFor returns the cached or freshly-parsed lockfile for the
// given workspace. The bool is false when the file is missing or the
// parse failed.
func (w *WorkspaceLockfiles) lockfileFor(ws pkgmgr.Workspace) (*Lockfile, bool) {
	path := w.resolve(ws)
	w.mu.Lock()
	defer w.mu.Unlock()
	if lf, hit := w.cache[path]; hit {
		return lf, lf != nil
	}
	lf, err := ParseLockfile(path)
	if err != nil {
		w.cache[path] = nil // negative cache so we don't retry per finding
		return nil, false
	}
	w.cache[path] = lf
	return lf, true
}
