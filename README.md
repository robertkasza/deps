# deps

CLI that scans a pnpm monorepo for npm vulnerabilities and remediates them by
editing `package.json` files (workspace bumps, parent bumps, or
`pnpm.overrides`), then regenerating the lockfile.

Built for the case off-the-shelf tools miss: transitive vulnerabilities that
have no parent fix and require a `pnpm.overrides` entry. Renovate silently
skips this case for pnpm; Dependabot doesn't generate pnpm overrides at all.

## Build

```
go build ./cmd/deps
```

Or install to `$GOPATH/bin`:

```
go install ./cmd/deps
```

## Commands

### `deps check`

Read-only. Scans workspaces, runs `pnpm audit`, walks the remediation ladder,
prints a plan.

```
deps check --dir /path/to/monorepo            # human output
deps check --dir /path/to/monorepo --json     # machine-readable
deps check --severity high                    # filter findings
deps check --concurrency 5                    # parallel audits (default 3)
```

### `deps fix`

Runs `check`, applies the resulting edits, runs `pnpm install`, re-audits to
verify each targeted advisory is gone.

```
deps fix --dir /path/to/monorepo
```

The remediation ladder per finding:

| Finding | Action |
| --- | --- |
| Direct dep, fix in same major | bump the version |
| Direct dep, only major-bump fixes | report unresolved |
| Transitive, parent has fix in same major | bump the parent |
| Transitive, only parent-major-bump fixes | report unresolved |
| Transitive, no parent fix exists | add `pnpm.overrides` entry |
| No fix published anywhere | report unresolved |

## Audit-ci allowlists

Both commands read `audit-ci.json` and `audit-ci.jsonc` from the repository root,
even when invoked inside a workspace. Add accepted advisory IDs to `allowlist`:

```json
{
  "allowlist": ["GHSA-xxxx-yyyy-zzzz"]
}
```

Matching findings are skipped during planning and post-fix verification. Skipped
counts appear on stderr; allowlisted findings are omitted from JSON and do not
cause a nonzero exit. If all findings are allowlisted, `fix` makes no changes.

- `.jsonc` supports comments and trailing commas.
- If both files exist, their entries are combined. Workspace-local files are ignored.
- Only exact GHSA strings are supported, not package names, numeric IDs, path rules,
  or object-form exceptions. Invalid/unsupported configurations fail with an error.
- Other audit-ci settings are ignored. Neither file is modified.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Clean — no findings |
| `10` | Actionable findings present, or unresolved findings remain after a successful fix |
| `20` | Some targeted advisory is still present after re-audit (`unresolved-after-apply`) |
| `1` | Tool error (install failed, write error, etc.) |

CI scripts can branch on these directly.

## Requirements

- pnpm installed and on `PATH` (we shell out to `pnpm audit` and `pnpm install`)
- A pnpm monorepo with a valid `pnpm-lock.yaml` (run `pnpm install` once first
  if cloning fresh)

## Status

`deps check` and `deps fix` are implemented, including root audit-ci allowlists,
and tested against a real-world fixture. See `DESIGN.md` for the backlog.

## More

- `DESIGN.md` — architecture, decisions, and roadmap
- `CLAUDE.md` — conventions for working in the codebase
