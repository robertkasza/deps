package pnpm

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"gopkg.in/yaml.v3"

	"github.com/robertkasza/deps/internal/pkgmgr"
)

// workspaceFile mirrors the subset of pnpm-workspace.yaml we read.
// Other fields (catalogs, settings, ...) are intentionally ignored.
type workspaceFile struct {
	Packages []string `yaml:"packages"`
}

// packageManifest is the subset of package.json we need at discovery time.
type packageManifest struct {
	Name string `json:"name"`
}

// DiscoverWorkspaces returns the list of workspaces in the monorepo
// rooted at root.
//
// Behavior:
//   - If <root>/pnpm-workspace.yaml exists, treat root as a monorepo
//     and expand the `packages:` globs (with `!` negation) relative to
//     root. The root itself is included with IsRoot=true (it's the only
//     place pnpm.overrides live).
//   - If pnpm-workspace.yaml is absent, treat root as a single-package
//     repo: return one synthetic workspace = root.
//   - The root must contain a package.json either way.
//
// Glob semantics aim to match pnpm/fast-glob: `*`, `**`, `?`, `[...]`,
// `{a,b}`, plus leading `!` for excludes. `node_modules` is always
// excluded implicitly.
func (a *Adapter) DiscoverWorkspaces(dir string) ([]pkgmgr.Workspace, error) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve root: %w", err)
	}

	// pnpm resolves the workspace root by walking up from the working
	// directory to the nearest pnpm-workspace.yaml; pnpm.overrides and the
	// minimumReleaseAge cooldown only take effect there. deps mirrors that
	// so running inside a member (e.g. `cd docs`) reads and writes shared
	// config at the real root instead of the member's own package.json
	// (where pnpm would silently ignore it).
	configRoot := findWorkspaceRoot(absDir)
	if configRoot == "" {
		// No pnpm-workspace.yaml anywhere up the tree: standalone repo.
		rootPkg := filepath.Join(absDir, "package.json")
		name, err := readPackageName(rootPkg)
		if err != nil {
			return nil, fmt.Errorf("read root package.json: %w", err)
		}
		return []pkgmgr.Workspace{{
			Dir:          absDir,
			RelDir:       "",
			PackageJSON:  rootPkg,
			MonorepoRoot: absDir,
			Name:         name,
			IsRoot:       true,
		}}, nil
	}

	all, err := a.discoverMembers(configRoot)
	if err != nil {
		return nil, err
	}

	// Invoked at the workspace root: operate on every member.
	if absDir == configRoot {
		return all, nil
	}

	// Invoked inside the tree: scope to the member(s) selected by absDir,
	// but every workspace keeps MonorepoRoot == configRoot so shared-config
	// edits (overrides, cooldown excludes) still land at the real root.
	if scoped := scopeToDir(all, absDir); len(scoped) > 0 {
		return scoped, nil
	}

	// absDir selects no declared member (e.g. a nested non-member dir).
	// If it has its own package.json, audit just it; otherwise fall back
	// to the whole workspace rather than auditing nothing.
	if name, err := readPackageName(filepath.Join(absDir, "package.json")); err == nil {
		rel, _ := filepath.Rel(configRoot, absDir)
		return []pkgmgr.Workspace{{
			Dir:          absDir,
			RelDir:       filepath.ToSlash(rel),
			PackageJSON:  filepath.Join(absDir, "package.json"),
			MonorepoRoot: configRoot,
			Name:         name,
			IsRoot:       false,
		}}, nil
	}
	return all, nil
}

// discoverMembers returns the root workspace plus every member declared
// by root's pnpm-workspace.yaml. All share MonorepoRoot == root, and
// member RelDir values are relative to root (matching pnpm's audit path
// encoding).
func (a *Adapter) discoverMembers(root string) ([]pkgmgr.Workspace, error) {
	rootPkg := filepath.Join(root, "package.json")
	rootName, err := readPackageName(rootPkg)
	if err != nil {
		return nil, fmt.Errorf("read root package.json: %w", err)
	}

	rootWS := pkgmgr.Workspace{
		Dir:          root,
		RelDir:       "",
		PackageJSON:  rootPkg,
		MonorepoRoot: root,
		Name:         rootName,
		IsRoot:       true,
	}

	patterns, err := readWorkspacePatterns(filepath.Join(root, "pnpm-workspace.yaml"))
	if err != nil {
		return nil, err
	}
	if patterns == nil {
		// Single-package repo.
		return []pkgmgr.Workspace{rootWS}, nil
	}

	includes, excludes := splitPatterns(patterns)

	matches, err := globWorkspaces(root, includes, excludes)
	if err != nil {
		return nil, err
	}

	out := []pkgmgr.Workspace{rootWS}
	for _, dir := range matches {
		if dir == root {
			continue // never duplicate the root
		}
		pj := filepath.Join(dir, "package.json")
		name, err := readPackageName(pj)
		if err != nil {
			// A directory matching the glob without a package.json is not
			// a workspace; skip silently (pnpm does the same).
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			// A package.json that exists but can't be parsed (empty,
			// truncated, or otherwise malformed — often a test fixture
			// vendored inside a dependency's source) must not abort
			// discovery of every other workspace. Warn and skip it.
			a.warnf("deps: skipping unreadable manifest %s: %v", pj, err)
			continue
		}
		rel, err := filepath.Rel(root, dir)
		if err != nil {
			return nil, fmt.Errorf("relpath %s: %w", dir, err)
		}
		out = append(out, pkgmgr.Workspace{
			Dir:          dir,
			RelDir:       filepath.ToSlash(rel),
			PackageJSON:  pj,
			MonorepoRoot: root,
			Name:         name,
			IsRoot:       false,
		})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Dir < out[j].Dir })
	return out, nil
}

// findWorkspaceRoot walks up from start (inclusive) to the nearest
// directory containing a pnpm-workspace.yaml, mirroring how pnpm locates
// the workspace root. Returns "" if none exists up to the filesystem root.
func findWorkspaceRoot(start string) string {
	dir := start
	for {
		if _, err := os.Stat(filepath.Join(dir, "pnpm-workspace.yaml")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// scopeToDir filters discovered members to those selected by absDir: a
// member is in scope if it sits at or below absDir (invoking from a dir
// containing several members) or if absDir sits within it (invoking from
// a member's subdirectory). The root workspace is never selected this
// way — it's returned only when the invocation dir IS the workspace root.
func scopeToDir(all []pkgmgr.Workspace, absDir string) []pkgmgr.Workspace {
	var out []pkgmgr.Workspace
	for _, ws := range all {
		if ws.IsRoot {
			continue
		}
		if dirWithin(ws.Dir, absDir) || dirWithin(absDir, ws.Dir) {
			out = append(out, ws)
		}
	}
	return out
}

// dirWithin reports whether path is at or below base.
func dirWithin(path, base string) bool {
	rel, err := filepath.Rel(base, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// readWorkspacePatterns returns the `packages:` globs from the YAML
// file, or nil if the file is absent.
func readWorkspacePatterns(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var f workspaceFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return f.Packages, nil
}

// splitPatterns separates include and exclude (leading `!`) globs.
// Empty entries are dropped.
func splitPatterns(patterns []string) (includes, excludes []string) {
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.HasPrefix(p, "!") {
			excludes = append(excludes, strings.TrimPrefix(p, "!"))
			continue
		}
		includes = append(includes, p)
	}
	return includes, excludes
}

// globWorkspaces expands include patterns relative to root, applies
// excludes, filters out node_modules paths, and returns absolute paths
// to directories containing a package.json. Results are deduplicated.
func globWorkspaces(root string, includes, excludes []string) ([]string, error) {
	rootFS := os.DirFS(root)
	seen := map[string]struct{}{}

	for _, pat := range includes {
		paths, err := doublestar.Glob(rootFS, pat)
		if err != nil {
			return nil, fmt.Errorf("glob %q: %w", pat, err)
		}
		for _, rel := range paths {
			if isIgnoredPath(rel) {
				continue
			}
			if matchesAny(rel, excludes) {
				continue
			}
			abs := filepath.Join(root, rel)
			info, err := os.Stat(abs)
			if err != nil || !info.IsDir() {
				continue
			}
			if _, err := os.Stat(filepath.Join(abs, "package.json")); err != nil {
				continue
			}
			seen[abs] = struct{}{}
		}
	}

	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out, nil
}

func matchesAny(path string, patterns []string) bool {
	for _, p := range patterns {
		ok, err := doublestar.Match(p, path)
		if err == nil && ok {
			return true
		}
	}
	return false
}

// isIgnoredPath reports whether a glob match should be skipped because it
// lies under a directory pnpm's own workspace scan never descends into:
// node_modules, or any hidden (dot-prefixed) directory such as .git, or
// direnv/nix caches like .direnv (which vendor dependency sources whose
// package.json fixtures may be empty or malformed). pnpm globs with
// fast-glob's dot:false, so `*`/`**` never match dot-segments there either;
// this keeps deps aligned with that behavior.
func isIgnoredPath(rel string) bool {
	parts := strings.Split(filepath.ToSlash(rel), "/")
	for _, p := range parts {
		if p == "node_modules" {
			return true
		}
		if len(p) > 1 && p[0] == '.' {
			return true
		}
	}
	return false
}

// warnf writes a non-fatal diagnostic line to the adapter's warn writer
// (stderr by default), ensuring it ends with a newline.
func (a *Adapter) warnf(format string, args ...any) {
	w := a.warnw
	if w == nil {
		w = os.Stderr
	}
	msg := fmt.Sprintf(format, args...)
	if !strings.HasSuffix(msg, "\n") {
		msg += "\n"
	}
	fmt.Fprint(w, msg)
}

func readPackageName(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var m packageManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return "", fmt.Errorf("parse %s: %w", path, err)
	}
	return m.Name, nil
}
