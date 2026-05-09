package pnpm

import (
	"fmt"
)

// Install runs `pnpm install` (with --lockfile-only when set) at root.
// Output is captured; on failure the combined stderr is included in
// the error message.
func (a *Adapter) Install(root string, lockfileOnly bool) error {
	run := a.runner
	if run == nil {
		run = defaultRunner
	}
	args := []string{"install"}
	if lockfileOnly {
		args = append(args, "--lockfile-only")
	}
	stdout, stderr, exit, runErr := run(root, "pnpm", args...)
	if runErr != nil {
		return fmt.Errorf("run pnpm install in %s: %w", root, runErr)
	}
	if exit != 0 {
		return fmt.Errorf("pnpm install in %s exited %d: %s",
			root, exit, trimForMsg(stderr, stdout))
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
