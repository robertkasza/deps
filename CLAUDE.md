# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Go CLI that scans a pnpm monorepo for npm vulnerabilities and remediates them by editing `package.json` files (workspace bumps, parent bumps, or `pnpm.overrides`), then regenerating the lockfile. Two commands: `deps check` (read-only plan) and `deps fix` (apply + reinstall + verify).

`DESIGN.md` is the source of truth for architecture, decisions, and backlog. Read it before making non-trivial changes.

## Common commands

```bash
# build
go build ./cmd/deps                          # produces ./deps in repo root

# run
./deps check --dir <monorepo>                # plan, no writes
./deps check --dir <monorepo> --json         # machine-readable plan
./deps fix   --dir <monorepo>                # apply + install --lockfile-only + re-audit

# test
go test ./...                                 # all packages
go test ./internal/plan/ -v -run TestBuild   # single test pattern
go test ./internal/pnpm/ -run TestParseAudit # single test by name

# manual smoke-test (the playground/ dir is gitignored)
./deps check --dir playground/vuln-test
./deps fix   --dir playground/vuln-test
```

## Architecture

Pipeline: `discover → audit → triage → plan → (fix only: apply → install --lockfile-only → re-audit)`. Each stage is a separate package; data flows through `pkgmgr.Workspace`, `Advisory`, `Finding`, `Edit`, `Plan`.

Three orthogonal layers:

- **Package-manager-specific** (`internal/pnpm/`) — discovery, audit, edit-writing, install. Behind `pkgmgr.PkgManager` interface so npm/yarn can slot in.
- **Generic remediation** (`internal/triage/`, `internal/plan/`, `internal/registry/`) — operates on abstract types, no pnpm awareness.
- **Orchestration** (`internal/checkcmd/`, `internal/fixcmd/`) — wires stages together, handles concurrency, formats output, sets exit codes.

## Conventions worth knowing

- **Runner injection.** `internal/pnpm/Adapter` has a `runner` field for shelling out to `pnpm`. Tests use `WithRunner(fakeRunner(...))` to avoid needing a real `pnpm` binary. Same pattern is what lets registry tests use `httptest.Server`. New shell-outs should follow the pattern.
- **Per-workspace audit, path-prefix filtering.** `pnpm audit --json` returns *global* output even when run from a workspace dir. We run it per workspace and filter findings by the `apps__admin>` style prefix encoded in advisory paths. `Workspace.RelDir` drives this.
- **Override target detection.** `internal/pnpm/override.go` tries `pnpm-workspace.yaml`'s `overrides:` first, then root `package.json`'s `pnpm.overrides`, then defaults to root `package.json` (matches `pnpm audit --fix`). Don't change this without reading SKILL.md and testing on both shapes.
- **Exit codes are a contract.** `0` clean · `10` actionable / unresolved present · `20` `unresolved-after-apply` · `1` tool error. CI scripts will branch on these — additive changes only.
- **stdout is structured output, stderr is progress.** `deps check --json > plan.json` must work cleanly. Don't `fmt.Fprintln(stdout)` for log lines.
- **JSON output is semi-public.** Additive changes after first release; never rename or remove fields.
- **Format preservation on JSON edits.** sjson is used because `encoding/json` would lose key order. When sjson must create a new nested key (rather than replace an existing one), output is re-pretty-formatted using detected indent (`detectJSONIndent`). New JSON edits should go through `internal/pnpm/bump.go` or `override.go` helpers, not stdlib marshal.
- **Concurrency is rate-limit-bound, not CPU-bound.** Default `--concurrency 3` keeps us under npm's per-IP audit rate limit. NumCPU is wrong; large monorepos can raise it manually.
- **Test fixtures live in `internal/<pkg>/testdata/`.** `audit_vuln-test.json` was captured from a real `pnpm audit --json` run. Re-capture if pnpm changes its output schema; update assertions accordingly.

## Things not to do

- Don't treat `pnpm audit` exit code 1 as failure. pnpm exits 1 when vulnerabilities are present — that's the signal, not an error. Errors are detected via empty stdout + non-empty stderr + runner launch error.
- Don't cache audit results across runs. Cache lifetime is one CLI invocation.
- Don't modify `pnpm-lock.yaml` directly. Always go through `Adapter.Install()`.
- Don't reformat user `package.json` files beyond what's required by the edit. Diff cleanliness matters for PRs.
- Don't write to `audit-ci.jsonc`. Allowlisting an advisory is the user's decision; we only *read* it (planned — see DESIGN.md "Required, not yet implemented").

## When you change a public surface

- A new flag → update both `checkcmd` and `fixcmd` if it makes sense in both, and document in `DESIGN.md`.
- A new edit kind → add to `pkgmgr.EditKind`, handle in `plan`, `apply` (`internal/pnpm/apply.go`), and JSON output (`internal/checkcmd/check.go::jsonEdit`).
- A new exit code → update both `cmd/deps/main.go` (codedError unwrap) and `DESIGN.md`'s contract.
