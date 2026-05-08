# deps

CLI tool that scans a pnpm monorepo for npm vulnerabilities and remediates them
following a fixed ladder: direct bump → parent bump → `pnpm.overrides` (root).

## Status

Scaffold only. Commands are wired up but unimplemented.

## Commands

- `deps check` — scan workspaces, classify advisories, emit a remediation plan. Read-only.
- `deps fix` — run `check`, then apply the plan (mutates `package.json` and lockfile).

## Build

```
go build ./cmd/deps
./deps check -h
```
