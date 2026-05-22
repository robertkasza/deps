package pnpm

import (
	"fmt"
)

// Install runs `pnpm install` at root. Output is captured; on failure
// the combined stderr is included in the error message.
func (a *Adapter) Install(root string) error {
	run := a.runner
	if run == nil {
		run = defaultRunner
	}
	stdout, stderr, exit, runErr := run(root, "pnpm", "install")
	if runErr != nil {
		return fmt.Errorf("run pnpm install in %s: %w", root, runErr)
	}
	if exit != 0 {
		return fmt.Errorf("pnpm install in %s exited %d: %s",
			root, exit, trimForMsg(stderr, stdout))
	}
	return nil
}

// AuditFixUpdate runs `pnpm audit --fix update` in the given workspace
// dir. This is the only way to apply a freshly-added
// minimumReleaseAgeExclude entry to an existing lockfile — plain
// `pnpm install` ignores yaml-only changes and considers the lockfile
// "already up to date." `--fix update` selects the exclude-list
// strategy (over the default `--fix override`) and triggers actual
// re-resolution.
//
// Run per workspace that has a cooldown-bypass edit, not at the root,
// because each workspace has its own lockfile (sharedWorkspaceLockfile
// may be false).
func (a *Adapter) AuditFixUpdate(workspaceDir string) error {
	run := a.runner
	if run == nil {
		run = defaultRunner
	}
	stdout, stderr, exit, runErr := run(workspaceDir, "pnpm", "audit", "--fix", "update")
	if runErr != nil {
		return fmt.Errorf("run pnpm audit --fix update in %s: %w", workspaceDir, runErr)
	}
	// pnpm audit exits 1 when it finds vulnerabilities, even after
	// --fix has done its work; that's not a tool failure for us.
	// Only treat exit codes > 1 as real errors (network failure, bad
	// args, etc.).
	if exit > 1 {
		return fmt.Errorf("pnpm audit --fix update in %s exited %d: %s",
			workspaceDir, exit, trimForMsg(stderr, stdout))
	}
	return nil
}

// trimForMsg returns the first non-empty of stderr or stdout, trimmed
// to a reasonable length for inclusion in error messages.
func trimForMsg(stderr, stdout []byte) string {
	pick := stderr
	if len(pick) == 0 {
		pick = stdout
	}
	const max = 1024
	if len(pick) > max {
		pick = pick[:max]
	}
	return string(pick)
}
