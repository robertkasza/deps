// Package workspace discovers pnpm workspaces from a monorepo root.
//
// It reads pnpm-workspace.yaml, expands the package globs, and returns
// the root + every workspace's package.json path.
package workspace

// TODO: implement Discover(root string) (Root, []Workspace, error).
