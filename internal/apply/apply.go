// Package apply mutates package.json files according to a Plan,
// runs `pnpm install --lockfile-only`, and re-verifies that targeted
// advisories are resolved.
package apply

// TODO: implement Apply(p plan.Plan, opts Options) (Result, error).
