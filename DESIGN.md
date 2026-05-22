# deps — Design

Captures the design decisions for `deps`. Update this as decisions change.

## Goal

A CLI that scans a pnpm monorepo for npm vulnerabilities and remediates them by editing `package.json` (workspace bumps, parent bumps, or `pnpm.overrides`), then regenerates the lockfile.

The motivating problem: in a pnpm monorepo where CI fails on any vulnerability, transitive vulns that have no parent fix require `pnpm.overrides`. No free off-the-shelf tool writes those automatically — Renovate silently skips this case, Dependabot doesn't generate pnpm overrides at all.

## Status

### Implemented

- **`deps check`** — discovery, audit per workspace, triage, plan, human + JSON output
- **`deps fix`** — `check` pipeline + apply edits + `pnpm install` + scoped re-audit
- Workspace discovery: parses `pnpm-workspace.yaml` (globs, negation), single-package fallback, `node_modules` exclusion
- Audit: shells out to `pnpm audit --json` per workspace, attributes findings via path-prefix encoding (`apps__admin>request`)
- Triage: direct vs transitive based on workspace's `package.json` deps fields; parent identification
- Plan (SKILL.md ladder): `bump-direct`, `bump-parent` (registry-validated), `exclude-from-cooldown`, `override-add`. Distinguishes `major-jump-required` from `no-fix-available`.
- **Cooldown-bypass (`exclude-from-cooldown`).** Between `bump-parent` and `override-add` on the transitive ladder. When pnpm's `minimumReleaseAge` filter is what's hiding a patched version from resolution (active via explicit `pnpm-workspace.yaml` setting or by default on pnpm ≥ 11), `deps` checks whether *every* importer of the vulnerable package declares a range that already permits the patched version. If so, it emits an `exclude-from-cooldown` edit that adds the exact patched version (`pkg@1.2.4`) to `minimumReleaseAgeExclude` in `pnpm-workspace.yaml` — no `pnpm.overrides`, cleaner diff, naturally expires. Detection is pure static analysis over the lockfile + registry manifests; no install. Exact-version syntax always (10.19+) so future publishes still soak through the cooldown.
- **Multi-advisory grouping.** Findings are grouped by `(workspace, package)` for direct deps and `(workspace, parent, vuln pkg)` for transitive deps before the ladder runs. One bump or override per group covers every advisory it can; overrides are merged across the workspace's vuln pkg (broadest vulnerable range, highest fixed target). Within a transitive group, a parent bump is preferred for any advisory it patches even when an override is also needed for a sibling advisory — overrides are sticky tech debt and we never use one when a parent bump would do.
- Apply: sjson-based JSON edits preserving format (key order, indent, trailing newline); yaml.v3 Node-API edits for `pnpm-workspace.yaml`. The applier is a flat writer — all grouping/dedup is the planner's responsibility.
- Override target detection: existing `pnpm-workspace.yaml.overrides` wins → existing `package.json.pnpm.overrides` → default to root `package.json` (matches `pnpm audit --fix`)
- Scoped re-audit per SKILL.md: only edited workspaces unless an override was added
- Concurrency control: `--concurrency` flag, default 3 (npm rate-limit-friendly)
- Exit codes: `0` clean · `10` actionable / unresolved present · `20` `unresolved-after-apply` · `1` tool error
- Tests across all packages with fakes for the runner and registry; real `pnpm audit --json` fixture in `internal/pnpm/testdata/`

### Required, not yet implemented

- **`audit-ci.jsonc` allowlist support.** The target repo (`nhost/nhost`) uses `audit-ci-recursive` whose allowlist must be honored. `deps` should read `audit-ci.jsonc` from the monorepo root and skip any advisory whose GHSA is allowlisted there — both in plan output (don't emit edits for it) and in re-audit verification (don't count as `unresolved-after-apply`). Without this, `deps` will repeatedly try to fix advisories the team has already accepted.

  Format (JSONC):
  ```jsonc
  {
    "moderate": true,
    "allowlist": ["GHSA-xxxx", "GHSA-yyyy"]
  }
  ```

  Implementation sketch:
  - Read + parse the file once during discovery.
  - Pass the allowlist into `audit` so filtered findings never reach triage.
  - Surface allowlisted findings only in a separate "skipped (allowlisted)" line in human output, omitted from JSON entirely (or under `skipped`).

- **`lockfile-refresh` edit kind.** A fourth rung at the top of the SKILL.md ladder for transitive findings where the *currently declared* dependency range in some workspace already admits a non-vulnerable version — the lockfile just has a stale resolution. Reference case: [nhost/nhost#4306](https://github.com/nhost/nhost/pull/4306), where `brace-expansion@5.0.5` was resolved under a `^5.0.5` range and `5.0.6` (a patch release) fixed the advisory. The PR touched only `pnpm-lock.yaml` files — zero `package.json` churn, no sticky override, no `pnpm.overrides` to remove later. We currently miss this and fall through to `bump-parent` or `override-add` unnecessarily.

  Detection (inside the transitive group, before the existing ladder runs):
  - For each advisory, walk the dep graph the audit already produced and find every declared range that resolves to the vulnerable package (parent → vuln pkg, grandparent → parent, etc., until the root range).
  - If any version in the advisory's `fixedIn` set satisfies the *unchanged* declared range, the lockfile alone can carry the fix. Emit `Edit{Kind: LockfileRefresh, Package: <vuln pkg>}` and skip the rest of the ladder for this finding.
  - The check is purely semver math against data we already have — no extra registry calls.

  Apply: no `package.json` write. The applier records the package name; `fix.go` aggregates these across the run and, after the existing `pnpm install` phase, issues `pnpm update <pkg> -r` (one invocation per affected package) at the monorepo root. `pnpm update -r` re-resolves a single transitive within its existing semver ranges across all workspaces and writes the result to the lockfile.

  Ordering note: `lockfile-refresh` must run *before* any `override-add` is considered for the same vuln pkg, otherwise we'd write a sticky override for a problem the existing range could have absorbed. Slot it as the new top of the ladder for transitives:

  | Transitive, declared range already admits a fix | `lockfile-refresh` |

  Re-audit scope: `lockfile-refresh` is repo-global like `override-add` (it can shift resolutions in workspaces we didn't visit), so its presence should force the full-repo re-audit branch in `fix.go`.

  JSON output: new entry under `edits[].kind = "lockfile-refresh"` with just `{kind, package, fromVersion, toVersion?}`. Additive — no rename of existing fields. New exit-code paths are not needed.

## Non-goals

- Routine non-security updates (Renovate territory).
- Multiple package managers — pnpm only at first; npm/yarn are future seams.
- Single-package repos as a primary use case (supported, but monorepo is the optimization target).
- Automatic ladder retry. Failed remediation candidate → reported, not silently swapped for the next rung.
- In-memory simulation of pnpm's resolver. Post-install re-audit is the ground truth.

## Architecture — modular adapters

Three orthogonal concerns separated by interface:

1. **Package manager** (`internal/pkgmgr` interface, `internal/pnpm` impl). Owns: workspace discovery, audit, override-writing, install. Future slots: `internal/npm`, `internal/yarn`.
2. **Repo layout** (single-package vs monorepo). Handled inside the pkgmgr's `DiscoverWorkspaces` — single-package returns one synthetic workspace.
3. **Remediation logic** (`triage`, `plan`, `registry`). Package-manager-agnostic. Operates on abstract `Advisory`, `Workspace`, `Edit`, `Plan`.

```go
type PkgManager interface {
    Name() string
    DiscoverWorkspaces(root string) ([]Workspace, error)
    Audit(ws Workspace) ([]Advisory, error)
    ApplyEdits(edits []Edit) error
    Install(root string, lockfileOnly bool) error
}
```

The CLI auto-detects the package manager at startup based on lockfile presence. Not a plugin system — clean interfaces in one statically-linked binary.

## Pipeline

```
DiscoverWorkspaces        ← pkgmgr
Audit (per workspace)     ← pkgmgr
triage                    ← generic: direct vs transitive, find top-level parent
plan                      ← generic: walk SKILL.md ladder, emit Edits
                              (registry-aided for parent-bump candidates)
─────── deps check stops here ───────
ApplyEdits (write Edits)  ← pkgmgr (writes to package.json + workspace.yaml)
Install                   ← pkgmgr (pnpm install)
re-audit                  ← pkgmgr (scoped per SKILL.md; full repo if any override was added)
report                    ← summary of applied / unresolved / unresolved-after-apply
```

### `triage`

Pure function over an advisory + that workspace's `package.json`. Produces a `Finding`:

- **Direct** if the package is in `dependencies` / `devDependencies` / `optionalDependencies` / `peerDependencies`.
- **Transitive** otherwise; record the top-level parent (first hop after the workspace prefix in the advisory's path).

No I/O beyond reading the package.json. No remediation decisions.

### `plan`

Groups findings, then walks the SKILL.md ladder per advisory within each group, emitting candidate `Edit`s (or pushing to `unresolved`).

**Grouping keys:**
- Direct findings: `(workspace, package)`. One `bump-direct` per group, target version = `pickSmallest` against the *intersection* of every group member's `FixedRange`.
- Transitive findings: `(workspace, parent, vuln pkg)`. The latest same-major parent's predicted vuln resolution is computed once; each advisory is checked against that prediction. Advisories the prediction clears collapse into a single `bump-parent`; the rest fall to override.
- Override edits are then merged across `(monorepoRoot, vuln pkg)` — broadest vulnerable range, highest fixed target — so `pnpm.overrides` stays minimal.

**Per-advisory ladder within a group:**

| Advisory shape | Plan output |
|---|---|
| Direct, fix in same major | participates in the group's `bump-direct` |
| Direct, fix requires major jump | `unresolved{reason: major-jump-required}` (group still bumps for the others) |
| Transitive, latest same-major parent's predicted resolution clears it | participates in the group's `bump-parent` |
| Transitive, only newer-major parent's predicted resolution clears it | `unresolved{reason: major-jump-required}` |
| Transitive, no parent version's predicted resolution clears it | contributes to an `override-add` (merged across the workspace's vuln pkg) |
| No fix published anywhere | `unresolved{reason: no-fix-available}` |

Override format (narrow, per SKILL.md):

```json
"<pkg>@<vulnerable-range>": "<min-fixed-version>"
```

`plan` consults the npm registry (`registry.npmjs.org` by default; respects `.npmrc` `registry=`) to know whether a non-major parent version exists that depends on a fixed version of the vuln package. In-process cache for the lifetime of one run.

## Validation strategy

`plan` produces *candidates*, not guarantees:

- **Direct bump / override** — provably correct in memory. The new constraint can't resolve to a vulnerable version.
- **Parent bump** — best-effort. We read the parent's manifest at the candidate version and check its declared dep on the vuln package. pnpm's actual resolution can still differ due to peer-deps, hoisting, existing overrides.

The authoritative check is **post-install re-audit**:

```
write Edits → pnpm install → pnpm audit --json → check the GHSA is gone
```

After all fixes:
- **Per-workspace re-audit** for direct + parent-bump edits (scoped, matches SKILL.md). Implemented: only edited workspaces are re-audited.
- **Full repo re-audit** if any `override-add` was applied (overrides are global).

Any GHSA from the plan still present after install is reported as `unresolved-after-apply`. No automatic ladder retry — the user reviews and decides.

## Audit strategy: per-workspace by default

`pnpm audit` (no flags) audits the importer in CWD. Whether it surfaces workspace vulns depends on `node-linker` (hoisted vs isolated) and what's declared in root `package.json`. The behavior is repo-dependent: in our small playground fixture, root audit happens to catch everything (hoisting); in `nhost/nhost`, root audit returns nothing — workspace audits are required.

Building for the per-workspace case is always correct. There is no safe shortcut to "audit once at root."

Concurrency is bounded (`--concurrency`, default 3) to stay under npm's rate limit.

## Output and CI-readiness

Deliberate constraints from day one:

- **Exit codes:** `0` clean · `10` actionable findings or unresolved present · `20` `unresolved-after-apply` · `1` tool error.
- **`--json` is a contract.** Additive changes only after first release. The future GitHub Action will parse this.
- **Deterministic output.** Stable key ordering in JSON; sorted advisory lists; no timestamps written into files. Same input → byte-identical output.
- **stdout vs stderr split.** Structured output → stdout; progress/log → stderr. `deps check --json > plan.json` works cleanly.
- **`fix` is a no-op when there's nothing to do.** Exit 0, write nothing, don't touch the lockfile. Prevents CRON runs from opening empty PRs.
- **No interactive prompts.** Anything SKILL.md asks a human about lands in `unresolved`. Future policy flags will narrow this.

## Future: CI integration

A GitHub Action wrapper, run on a schedule, opens PRs with remediations.

Out of scope for `deps` itself. Lives in a separate repo. The CLI stays git-host-agnostic; the Action knows about GitHub. The constraints above ("Output and CI-readiness") make that integration painless when we get to it.

## MVP simplifications (deliberate)

1. **Single package manager (pnpm).** Interfaces in place for npm/yarn later.
2. **Single root.** Standard pnpm workspace = exactly one root with `pnpm-workspace.yaml`.
3. **No in-memory pnpm resolver.** Post-install audit is the source of truth.
4. **No automatic ladder retry.** Failed candidate → reported, not silently swapped.
5. **Direct HTTP to `registry.npmjs.org`.** Respect `registry=` in `.npmrc`. No auth handling for private registries yet.
6. **No interactive prompts.** Major-jump and ambiguous cases land in `unresolved`. Policy flags (`--max-major-jump`, `--prefer=bump|override`) are future work.

## Project layout

```
cmd/deps/                  entrypoint
internal/
  cli/                     subcommand dispatch (check, fix)
  checkcmd/                deps check
  fixcmd/                  deps fix
  pkgmgr/                  PkgManager interface + shared types
  pnpm/                    pnpm adapter (audit, install, write override, bump)
  triage/                  direct vs transitive + parent identification
  plan/                    SKILL.md ladder → Edits
  registry/                npm registry HTTP client + in-process cache
  report/                  (placeholder) JSON / human formatters
playground/                hand-built fixtures for manual smoke-testing
```

## Polish items (backlog)

Things that work but could be nicer. Each is small, none are blocking.

- **`deps version` command (or `--version` flag).** Prints the binary's version, build commit, Go version. Use `runtime/debug.ReadBuildInfo` so it works for both `go install` and `go build`. Add a stable VCS stamp via `-ldflags "-X main.version=..."` for release builds.
- **Suppress / collapse pnpm's noisy retry warnings.** `pnpm audit` writes "Will retry in 10 seconds" to stderr on rate-limit. Currently visible to the user; could be filtered.
- **Real `--severity` filter.** Today the flag filters at display only — plan still walks every finding. Could short-circuit before plan for speed.
- **Better error messages for missing lockfile.** Currently surfaces pnpm's raw error; could detect and tell the user to run `pnpm install` first.
- **`internal/report/`** is still a stub. Move the per-formatter logic out of `checkcmd` / `fixcmd` to make the human/JSON outputs reusable across commands.
- **Display improvements.** Group human output by remediation kind, color severity tags, etc.

## Future features (not yet planned for an MVP+1)

- **`deps prune` — clean up unused overrides.** Identify and optionally remove `pnpm.overrides` entries that are no longer needed (target package no longer in the tree, or a newer parent already ships a fixed transitive). Two modes:
  - *Conservative (default, read-only):* report likely-unused entries based on `pnpm why` / lockfile inspection. Heuristic, fast, zero risk.
  - *Authoritative (`--apply`):* test by removal — for each candidate, drop the override, run `pnpm install --lockfile-only`, re-audit. Keep removed if no targeted advisory resurfaces; restore otherwise. Slow but ground-truth.

  Helps keep the override list from growing forever as parent packages get bumped over time.

- **`deps prune` for `minimumReleaseAgeExclude` entries.** Sibling to the overrides-prune entry above: scheduled weekly run that removes exclude entries whose versions have aged past the cooldown threshold (registry publish time + `minimumReleaseAge` ≤ now). Keep this out of `deps fix` — bundling stale-entry cleanup into fix PRs bloats reviews with off-topic removals. Narrow exception inside `deps fix`: an exclude entry may be removed in the same pass when *this run's own remediation* makes it redundant (e.g. a parent bump shifts resolution so the prior exclude no longer matches anything in the tree).

- **`--max-major-jump <N>` / `--allow-major`.** Let users opt into auto-applying major-version bumps that today land in `unresolved{major-jump-required}`.
- **`--prefer=bump|override`.** When both a parent bump and an override could resolve the vuln, override the default.
- **npm / yarn adapters.** Slot into `internal/npm/`, `internal/yarn/`. The pkgmgr seam is already in place.
- **Auth handling for private registries** (e.g., `_authToken=`).
- **GitHub Action wrapper repo.** Schedule + PR creation; thin wrapper around `deps fix`.
- **Telemetry / dry-run preview as JSON diff.** A way to show "what would `fix` change" without touching disk, beyond what `check` already shows.
- **Bundled `pnpm` integration (no shellout).** Speculative; would require reimplementing pnpm's resolver — almost certainly not worth it.

## Open questions

1. **`audit-ci.jsonc` parse format.** Different versions of `audit-ci` have used different schemas (top-level allowlist vs. per-severity). Need to settle on one or accept both.
2. **Where to surface allowlisted advisories in output.** Hide entirely, or show under a `skipped` section?
3. **Should `deps fix` ever update an existing override** when re-audit shows the original range was insufficient? Today it leaves it; SKILL.md says "widen the range or revert."

## Cleanup before calling it 1.0

A code-quality pass we owe ourselves before treating this as done. Each is a real, identified issue; none are blocking the tool from working.

- **`internal/report/` is a stub.** Output-formatting logic lives inside `checkcmd` and `fixcmd`, duplicated between them. Move both human and JSON formatters into `internal/report/` so each command writes a single line of "format this Plan + WorkspaceResults" and the code path is shared.
- **`processAll` is duplicated in `checkcmd` and `fixcmd`.** Near-identical bodies (audit → triage → plan per workspace, bounded concurrency, progress reporting). Extract to one place — likely `internal/pipeline/` — once the API is stable. Was reasonable while we were iterating; less so now that both copies have drifted only by what they wrap around.
- **No real integration test against pnpm.** All tests use fakes. When pnpm changes its audit JSON or override semantics, we won't notice until a real run breaks. A skip-by-default test that runs `pnpm audit` on `playground/vuln-test` would catch regressions cheaply.
- **Inconsistent error message style.** Some surface as `deps: <wrap>: <inner>` (multi-level wrapping), some as flat strings. Not bad; not deliberate either. Worth a pass to settle on one shape.

## Things to watch

Bugs we noticed but haven't reproduced cleanly. Keep an eye out.

- ~~**Key reordering on `writeBump`.**~~ **Resolved — root cause is pnpm 10, not us.** Reproduced on nhost with a clean tree: `git checkout -- . && pnpm install --lockfile-only` (with or without `--frozen-lockfile`) mutates workspace `package.json` files on its own. pnpm 10 syncs `pnpm.overrides` rules into any workspace whose declared range overlaps an override's selector — it rewrites the declared range to the override's target value, sorts the deps block alphabetically, and emits a blank line as part of its formatter. Every diff matched an existing override exactly (esbuild `^0.24.0`→`>=0.25.0` via `esbuild@<=0.24.2`; postcss `^8.4.38`→`>=8.5.10` via `postcss@<8.5.10`; svelte `^5.38.1`→`>=5.53.5` via `svelte@<=5.53.4`). `sjson.SetBytes` in `writeBump` was innocent. The `@jest/globals` move in `services/functions` was pnpm's alphabetical sort during its rewrite of esbuild.

  **Needs discussion — how should `deps fix` handle this?** On any repo with pre-existing `pnpm.overrides`, our post-edit `pnpm install --lockfile-only` will broaden the diff with pnpm-induced rewrites we didn't plan. Worse, adding a *new* override during `fix` will then propagate into workspace files on the next install. Options to weigh:
  1. **Snapshot & restore.** Snapshot every workspace `package.json` before install; after install, restore any change that wasn't in our planned `Edit` set. Keeps diffs clean but fights pnpm — risk that pnpm refuses to install with "stale" workspace files on the next run.
  2. **Detect & report.** Don't fight pnpm — diff workspace files after install, surface pnpm-induced changes as a warning (or a new exit code) alongside our planned edits. Pushes the user to decide.
  3. **Skip install in `fix`.** Apply edits, leave lockfile + reconciliation to the user. Loses re-audit verification.
  4. **Accept it.** Document the behavior; let pnpm's rewrites land in the PR as-is.

  Decision pending. Until then, `deps fix` on repos with existing overrides will produce diffs that include pnpm reconciliation noise.

## Reference

- `SKILL.md` (in the repo root, gitignored locally) — the prose form of the remediation ladder this tool encodes.
