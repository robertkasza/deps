package pnpm

import (
	"bytes"
	"fmt"
	"os/exec"

	"github.com/robertkasza/deps/internal/pkgmgr"
)

// Runner executes an external command in a working directory and
// returns its stdout, stderr, and exit code. It is overridable on the
// Adapter so tests can fake `pnpm` without a real binary on PATH.
//
// runErr is non-nil only on genuine launch failures (binary not found,
// permission denied). A non-zero exit code is reported via exitCode and
// is not itself an error — `pnpm audit` exits 1 when vulnerabilities
// are present, which is a normal signal we still want to parse.
type Runner func(dir, name string, args ...string) (stdout, stderr []byte, exitCode int, runErr error)

func defaultRunner(dir, name string, args ...string) ([]byte, []byte, int, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return outBuf.Bytes(), errBuf.Bytes(), exitErr.ExitCode(), nil
		}
		return outBuf.Bytes(), errBuf.Bytes(), -1, err
	}
	return outBuf.Bytes(), errBuf.Bytes(), 0, nil
}

// Audit runs `pnpm audit --json` in ws.Dir and returns advisories
// originating in ws. pnpm exits 1 when vulnerabilities are present —
// that is treated as success as long as stdout is parseable JSON.
func (a *Adapter) Audit(ws pkgmgr.Workspace) ([]pkgmgr.Advisory, error) {
	run := a.runner
	if run == nil {
		run = defaultRunner
	}
	stdout, stderr, _, runErr := run(ws.Dir, "pnpm", "audit", "--json")
	if runErr != nil {
		return nil, fmt.Errorf("run pnpm audit in %s: %w", ws.Dir, runErr)
	}
	if len(stdout) == 0 {
		return nil, fmt.Errorf("pnpm audit produced no output in %s: %s", ws.Dir, string(stderr))
	}
	return parseAudit(stdout, ws)
}
