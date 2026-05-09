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
func (a *Adapter) DiscoverWorkspaces(root string) ([]pkgmgr.Workspace, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve root: %w", err)
	}

	rootPkg := filepath.Join(absRoot, "package.json")
	rootName, err := readPackageName(rootPkg)
	if err != nil {
		return nil, fmt.Errorf("read root package.json: %w", err)
	}

	rootWS := pkgmgr.Workspace{
		Dir:         absRoot,
		PackageJSON: rootPkg,
		Name:        rootName,
		IsRoot:      true,
	}

	wsYAML := filepath.Join(absRoot, "pnpm-workspace.yaml")
	patterns, err := readWorkspacePatterns(wsYAML)
	if err != nil {
		return nil, err
	}
	if patterns == nil {
		// Single-package repo.
		return []pkgmgr.Workspace{rootWS}, nil
	}

	includes, excludes := splitPatterns(patterns)

	matches, err := globWorkspaces(absRoot, includes, excludes)
	if err != nil {
		return nil, err
	}

	out := []pkgmgr.Workspace{rootWS}
	for _, dir := range matches {
		if dir == absRoot {
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
			return nil, fmt.Errorf("read %s: %w", pj, err)
		}
		out = append(out, pkgmgr.Workspace{
			Dir:         dir,
			PackageJSON: pj,
			Name:        name,
			IsRoot:      false,
		})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Dir < out[j].Dir })
	return out, nil
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
			if isUnderNodeModules(rel) {
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

func isUnderNodeModules(rel string) bool {
	parts := strings.Split(filepath.ToSlash(rel), "/")
	for _, p := range parts {
		if p == "node_modules" {
			return true
		}
	}
	return false
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
