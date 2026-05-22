package pnpm

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// minimumReleaseAgeRaw decodes either an int or a string from yaml.
// pnpm-workspace.yaml usually has it as an int; user-edited files
// occasionally quote it.
type minimumReleaseAgeRaw struct {
	set   bool
	value int
}

func (m *minimumReleaseAgeRaw) UnmarshalYAML(n *yaml.Node) error {
	m.set = true
	v, err := strconv.Atoi(strings.TrimSpace(n.Value))
	if err != nil {
		// Unparseable: treat as "not explicitly set" so we fall back
		// to the pnpm version default rather than silently disabling.
		m.set = false
		return nil
	}
	m.value = v
	return nil
}

// CooldownActive reports whether pnpm will currently apply an install
// cooldown (minimumReleaseAge) in the monorepo rooted at root.
//
// Decision order:
//  1. If pnpm-workspace.yaml sets minimumReleaseAge to a positive
//     number, cooldown is active.
//  2. If pnpm-workspace.yaml sets it to 0, cooldown is explicitly
//     disabled.
//  3. Otherwise, fall back to the resolved pnpm version: pnpm >= 11
//     ships minimumReleaseAge: 1440 as a default.
//
// Limitations:
//   - Only pnpm-workspace.yaml is consulted. pnpm also accepts the
//     setting via .npmrc and a root package.json "pnpm" block; we
//     don't read those today. The worst-case effect is that we don't
//     emit a cooldown-bypass edit when one would have worked, and
//     fall through to override.
//   - `pnpm --version` is invoked via the adapter's runner so tests
//     can fake it.
func (a *Adapter) CooldownActive(root string) (bool, error) {
	if active, set, err := readWorkspaceCooldown(root); err != nil {
		return false, err
	} else if set {
		return active, nil
	}
	major, err := a.pnpmMajorVersion(root)
	if err != nil {
		return false, err
	}
	return major >= 11, nil
}

// workspaceCooldownYAML is the subset of pnpm-workspace.yaml we read
// for cooldown configuration. minimumReleaseAge is documented as a
// number of minutes; the custom unmarshaler tolerates string forms.
type workspaceCooldownYAML struct {
	MinimumReleaseAge minimumReleaseAgeRaw `yaml:"minimumReleaseAge"`
}

// readWorkspaceCooldown returns (active, explicitlySet, err). When
// explicitlySet is false the caller should fall back to the pnpm
// version default. When the yaml exists but doesn't mention the key,
// explicitlySet is false (not an error).
func readWorkspaceCooldown(root string) (bool, bool, error) {
	path := filepath.Join(root, "pnpm-workspace.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, false, nil
		}
		return false, false, err
	}
	var w workspaceCooldownYAML
	if err := yaml.Unmarshal(raw, &w); err != nil {
		return false, false, err
	}
	if !w.MinimumReleaseAge.set {
		return false, false, nil
	}
	return w.MinimumReleaseAge.value > 0, true, nil
}

// pnpmMajorVersion shells out to `pnpm --version` and returns the
// integer major version (e.g., 11 for "11.5.0"). Uses the adapter's
// runner so tests can stub it.
func (a *Adapter) pnpmMajorVersion(root string) (int, error) {
	run := a.runner
	if run == nil {
		run = defaultRunner
	}
	stdout, _, exit, runErr := run(root, "pnpm", "--version")
	if runErr != nil {
		return 0, runErr
	}
	if exit != 0 {
		return 0, nil
	}
	v := strings.TrimSpace(string(stdout))
	if i := strings.IndexByte(v, '.'); i > 0 {
		v = v[:i]
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, nil
	}
	return n, nil
}
