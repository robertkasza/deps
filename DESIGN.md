# deps — Design

Captures the design decisions made before implementation. Update this as decisions change.

## Goal

A CLI that scans a pnpm monorepo for npm vulnerabilities and remediates them by editing `package.json` files (workspace bumps, parent bumps, or root-level `pnpm.overrides`), then regenerates the lockfile.

The motivating problem: in a pnpm monorepo where CI fails on any vulnerability, transitive vulns that have no parent fix require `pnpm.overrides`. No free off-the-shelf tool writes those automatically — Renovate silently skips this case, Dependabot doesn't generate pnpm overrides at all.

## Non-goals (for now)

- Routine non-security updates (Renovate territory).
- Multiple package managers — pnpm only at first; npm/yarn are future seams.
- Single-package repos — design supports them trivially (one synthetic workspace), but monorepo is the case we're optimizing for.
- Automatic ladder retry (if a chosen remediation doesn't actually fix the advisory after install, report it; don't auto-fall-back).
- In-memory simulation of pnpm's resolver. Post-install re-audit is the ground truth.

## MVP scope

Two commands:

- `deps check` — read-only. Discover workspaces, run `pnpm audit` per workspace, triage findings, plan remediations, emit a report.
- `deps fix` — `check` + apply edits + `pnpm install --lockfile-only` + re-audit to verify.

Non-interactive throughout. Anything SKILL.md asks a human about (major-version parent bump, ambiguous cases) lands in an `unresolved` list — never auto-decided in MVP. Policy flags can relax this later.

## Architecture — modular adapters

Three orthogonal concerns separated by interface:

1. **Package manager** (`internal/pkgmgr` interface, `internal/pnpm` impl). Owns: workspace discovery, audit, override-writing, install. Future slots: `internal/npm`, `internal/yarn`.
2. **Repo layout** (single-package vs monorepo). Handled inside the pkgmgr's `DiscoverWorkspaces` — single-package = one synthetic workspace.
3. **Remediation logic** (`triage`, `plan`, `registry`). Package-manager-agnostic. Operates on abstract `Advisory`, `Workspace`, `PackageJSON`, `Edit`.

Sketch:

```go
type PkgManager interface {
    Name() string
    DiscoverWorkspaces(root string) ([]Workspace, error)
    Audit(ws Workspace) ([]Advisory, error)
    WriteOverride(rootPkgJSON, pkg, vulnRange, fixedRange string) error
    Install(root string, lockfileOnly bool) error
}
```

The CLI auto-detects the package manager at startup (`pnpm-lock.yaml` → pnpm). Not a plugin system — no dynamic loading, just clean interfaces in one statically-linked binary.

## Pipeline

```
DiscoverWorkspaces        ← pkgmgr
Audit (per workspace)     ← pkgmgr
triage                    ← generic: direct vs transitive, find top-level parent
plan                      ← generic: walk SKILL.md ladder, emit Edits
                              (registry-aided for parent-bump candidates)
─────── check stops here ───────
apply (write Edits)       ← pkgmgr (writes to package.json)
Install --lockfile-only   ← pkgmgr
re-audit                  ← pkgmgr (per-workspace; root-recursive if any override added)
report                    ← generic
```

### `triage`

Pure function over an advisory + that workspace's `package.json`. Produces a `Finding`:

- **Direct** if the package is in `dependencies` / `devDependencies`.
- **Transitive** otherwise; record the top-level parent (first hop after `.` in the advisory's path).

No I/O beyond reading the package.json. No remediation decisions.

### `plan`

Walks the SKILL.md ladder per finding and emits candidate `Edit`s (or pushes to `unresolved`).

| Finding | Plan output |
|---|---|
| Direct, fix in same major | `Edit{kind: bump-direct}` |
| Direct, fix requires major jump | `unresolved{reason: major-jump-required}` |
| Transitive, parent has fix in current major | `Edit{kind: bump-parent}` |
| Transitive, only parent-major-bump fixes | `unresolved{reason: major-jump-required}` |
| Transitive, no parent fix exists | `Edit{kind: override-add}` (or `override-consolidate` if existing root override overlaps) |
| No fix published anywhere | `unresolved{reason: no-fix-available}` |

Override format (narrow, per SKILL.md):

```json
"<pkg>@<vulnerable-range>": "<min-fixed-version>"
```

`plan` consults the registry to know whether a non-major parent version exists that depends on a fixed version of the vuln package. Best-effort prediction only — see "Validation strategy" below.

## Validation strategy

`plan` produces *candidates*, not guarantees:

- **Direct bump / override** — provably correct in memory. The new constraint can't resolve to a vulnerable version.
- **Parent bump** — best-effort. We read the parent's manifest at the candidate version and check its declared dep on the vuln package. pnpm's actual resolution can still differ due to peer-deps, hoisting, existing overrides.

The authoritative check is **post-install re-audit**:

```
write Edits → pnpm install --lockfile-only → pnpm audit --json → check the GHSA is gone
```

After all fixes:
- **Per-workspace re-audit** for direct + parent-bump edits (scoped, matches SKILL.md).
- **Root-level recursive audit** if any `pnpm.overrides` entry was added (overrides are global, matches SKILL.md).

Any GHSA from the plan still present after install is reported as `unresolved-after-apply`. No automatic ladder retry in MVP.

## Audit strategy: per-workspace by default

`pnpm audit` (no flags) audits the importer in CWD — root-only if run at the root. Whether that surfaces workspace vulns depends on `node-linker` (hoisted vs isolated) and what's declared in root `package.json`. In the test fixture, root deps + hoisting made root audit "happen to" catch everything. In `nhost/nhost`, root audit finds nothing — workspace audits are required.

Building for the per-workspace case is always correct. We can add a fast-path optimization later (`pnpm -r`-style root pass, fall back to per-workspace if attribution is missing).

## Output and CI-readiness

Deliberate constraints from day one — refactoring these later is annoying:

- **Exit codes:** `0` clean · `10` actionable · `20` unresolved · `1` tool error. Stable. CI scripts branch on these.
- **`--format json` is a contract.** Additive changes only after first release. The future GitHub Action will parse this.
- **Deterministic output.** Stable key ordering in JSON; sorted advisory lists; no timestamps written into files. Same input → byte-identical output. Otherwise PRs churn for no reason.
- **stdout vs stderr split.** Structured output → stdout; progress/log → stderr. `deps check --format json > plan.json` must work.
- **`fix` is a no-op when there's nothing to do.** Exit 0, write nothing, don't touch the lockfile. Prevents CRON runs from opening empty PRs.

## Future: CI integration (notes, not MVP)

Eventual goal: a GitHub Action wrapper, run on a schedule, opens PRs with remediations.

Out of scope for `deps` itself. Lives in a separate repo. The CLI stays git-host-agnostic; the Action knows about GitHub. The constraints above ("Output and CI-readiness") are what make that integration painless when we get to it. No further design decisions needed inside `deps` today.

## MVP simplifications (deliberate)

1. **Single package manager (pnpm).** Interfaces in place for npm/yarn later, but no implementations.
2. **Single root.** Standard pnpm workspace = exactly one root with `pnpm-workspace.yaml`. `pnpm.overrides` go there.
3. **No in-memory pnpm resolver.** Post-install audit is the source of truth.
4. **No automatic ladder retry.** Failed candidate → reported, not silently swapped for the next rung.
5. **Direct HTTP to `registry.npmjs.org`.** Respect `registry=` in `.npmrc`. No auth handling for private registries yet.
6. **Non-interactive only.** Major-jump and ambiguous cases land in `unresolved`. Interactive prompts and policy flags (`--max-major-jump`, `--prefer=bump|override`) are future work.
7. **No `audit-ci.jsonc` allowlist support.** SKILL.md treats it as a last resort; we don't write to it. Later we can read it to skip already-allowlisted advisories.

## Project layout (target)

```
cmd/deps/                  entrypoint
internal/
  cli/                     subcommand dispatch (check, fix)
  checkcmd/                deps check
  fixcmd/                  deps fix
  pkgmgr/                  PkgManager interface + shared types
  pnpm/                    pnpm adapter (audit, install, write override)
  triage/                  direct vs transitive + parent identification
  plan/                    SKILL.md ladder → Edits
  registry/                npm registry client (HTTP, in-process cache)
  report/                  JSON / human / markdown formatters
```

Current scaffold has `workspace/`, `audit/`, `apply/` as separate empty packages — those will fold into `pnpm/` once we restructure to match this target.

## Open questions

1. **Naming of the `apply` step.** Currently a method on `PkgManager` (no separate package). Fine to leave.
2. **What to do when `audit-ci.jsonc` exists** — read it to skip allowlisted advisories, or ignore? (Probably: read it, skip. Later.)
3. **Concurrency for per-workspace audits.** Parallelize, bounded. Default = NumCPU. Worth measuring before tuning.
4. **`pnpm install` vs `pnpm install --lockfile-only`.** Lockfile-only is faster and what we want for `fix`'s verification step. But the post-install audit may need `node_modules` present. Confirm during implementation.
5. **Error handling when `pnpm audit` itself fails** (e.g., registry timeout, malformed lockfile). Should be a tool error (`exit 1`), not silent.

## Reference

- `SKILL.md` (in the parent context, gitignored locally) — the prose form of the remediation ladder this tool encodes.
