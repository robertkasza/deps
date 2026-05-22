package pnpm

import (
	"fmt"
	"os"
	"strings"

	"github.com/Masterminds/semver/v3"
	"gopkg.in/yaml.v3"

	"github.com/robertkasza/deps/internal/pkgmgr"
)

// Lockfile is the minimal subset of pnpm-lock.yaml (v9) we read.
// It deliberately ignores fields we don't need (resolution hashes,
// engines, deprecated flags, transitivePeerDependencies, etc.).
type Lockfile struct {
	Version   string
	Importers map[string]Importer
	Snapshots map[string]Snapshot
}

// Importer is the resolved dependency block for a single workspace
// (or "." for the monorepo root). It mirrors the importers: section
// of pnpm-lock.yaml.
type Importer struct {
	Dependencies         map[string]ImporterDep
	DevDependencies      map[string]ImporterDep
	OptionalDependencies map[string]ImporterDep
}

// ImporterDep is one workspace-declared dep. Specifier carries the
// range originally written in the workspace's package.json (e.g.,
// "^4.17.20"); Version is the version pnpm resolved it to.
type ImporterDep struct {
	Specifier string `yaml:"specifier"`
	Version   string `yaml:"version"`
}

// Snapshot is one entry in the snapshots: section. Dependencies maps
// dep-name → resolved version (possibly with a peer-dep suffix that
// callers must strip with BareVersion).
type Snapshot struct {
	Dependencies map[string]string
}

// rawLockfile is the on-disk shape we unmarshal into. The public
// Lockfile struct is a slightly normalized view of this.
type rawLockfile struct {
	LockfileVersion string                       `yaml:"lockfileVersion"`
	Importers       map[string]rawImporter       `yaml:"importers"`
	Snapshots       map[string]rawSnapshotEntry  `yaml:"snapshots"`
}

type rawImporter struct {
	Dependencies         map[string]ImporterDep `yaml:"dependencies"`
	DevDependencies      map[string]ImporterDep `yaml:"devDependencies"`
	OptionalDependencies map[string]ImporterDep `yaml:"optionalDependencies"`
}

type rawSnapshotEntry struct {
	Dependencies         map[string]string `yaml:"dependencies"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies"`
}

// ParseLockfile reads and parses pnpm-lock.yaml at the given path.
// Returns an error if the file is missing, unreadable, malformed,
// or has a lockfileVersion we don't support (anything but v9.x).
func ParseLockfile(path string) (*Lockfile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read lockfile: %w", err)
	}
	var r rawLockfile
	if err := yaml.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("parse lockfile: %w", err)
	}
	if !strings.HasPrefix(r.LockfileVersion, "9.") {
		return nil, fmt.Errorf("unsupported lockfileVersion %q (need 9.x)", r.LockfileVersion)
	}
	lf := &Lockfile{
		Version:   r.LockfileVersion,
		Importers: make(map[string]Importer, len(r.Importers)),
		Snapshots: make(map[string]Snapshot, len(r.Snapshots)),
	}
	for k, v := range r.Importers {
		lf.Importers[k] = Importer{
			Dependencies:         v.Dependencies,
			DevDependencies:      v.DevDependencies,
			OptionalDependencies: v.OptionalDependencies,
		}
	}
	for k, v := range r.Snapshots {
		// Merge dependencies + optionalDependencies for our purposes —
		// both can pull a vulnerable package into the tree.
		deps := make(map[string]string, len(v.Dependencies)+len(v.OptionalDependencies))
		for n, ver := range v.Dependencies {
			deps[n] = ver
		}
		for n, ver := range v.OptionalDependencies {
			deps[n] = ver
		}
		lf.Snapshots[k] = Snapshot{Dependencies: deps}
	}
	return lf, nil
}

// ImportersOf returns every edge in the resolved tree where pkg@version
// is pulled in as a direct dependency. The result covers both workspace
// declarations and transitive (snapshot) declarations.
func (l *Lockfile) ImportersOf(pkg, version string) []pkgmgr.ImporterEdge {
	return l.importers(pkg, func(resolved string) bool {
		return resolved == version
	})
}

// ImportersOfRange is ImportersOf for any resolved version satisfying
// the given npm semver range (e.g., advisory.VulnerableRange "<2.5.1").
// Returns an empty slice if vulnRange is unparseable.
func (l *Lockfile) ImportersOfRange(pkg, vulnRange string) []pkgmgr.ImporterEdge {
	c, err := semver.NewConstraint(vulnRange)
	if err != nil {
		return nil
	}
	return l.importers(pkg, func(resolved string) bool {
		v, err := semver.NewVersion(resolved)
		if err != nil {
			return false
		}
		return c.Check(v)
	})
}

// importers is the shared walker behind ImportersOf and
// ImportersOfRange. The match predicate decides which resolved
// versions count.
//
// Two sources of importer edges are scanned in the snapshots section:
//  1. The snapshot's own dependencies/optionalDependencies block —
//     covers regular and auto-installed-peer transitives.
//  2. The peer-context suffix in the snapshot key itself (e.g.,
//     "@expo/vector-icons@13.0.0(react@18.2.0)(ws@8.12.1)"). pnpm
//     encodes peer resolutions there even when the peer doesn't
//     appear in the dependencies block (autoInstallPeers=false,
//     or peer satisfied by an external/hoisted version).
//
// Only depth-1 peer tuples are extracted from the key; nested ones
// (e.g. "(react@19(react-native@0.73))" — react-native is react's
// peer context, not the outer package's) are correctly ignored.
//
// Duplicate edges across the two sources are de-deduped.
func (l *Lockfile) importers(pkg string, match func(resolved string) bool) []pkgmgr.ImporterEdge {
	var edges []pkgmgr.ImporterEdge
	seen := map[string]bool{}

	add := func(e pkgmgr.ImporterEdge) {
		key := edgeDedupKey(e)
		if seen[key] {
			return
		}
		seen[key] = true
		edges = append(edges, e)
	}

	for wsDir, imp := range l.Importers {
		for _, block := range []map[string]ImporterDep{
			imp.Dependencies, imp.DevDependencies, imp.OptionalDependencies,
		} {
			dep, ok := block[pkg]
			if !ok {
				continue
			}
			if !match(BareVersion(dep.Version)) {
				continue
			}
			add(pkgmgr.ImporterEdge{
				IsWorkspace:   true,
				ImporterName:  wsDir,
				DeclaredRange: dep.Specifier,
			})
		}
	}

	for snapKey, snap := range l.Snapshots {
		name, ver := splitSnapshotKey(snapKey)
		if name == "" {
			continue
		}
		if resolved, ok := snap.Dependencies[pkg]; ok && match(BareVersion(resolved)) {
			add(pkgmgr.ImporterEdge{
				ImporterName:    name,
				ImporterVersion: ver,
			})
		}
		for _, peer := range parsePeerContext(snapKey) {
			if peer.Name != pkg {
				continue
			}
			if !match(BareVersion(peer.Version)) {
				continue
			}
			add(pkgmgr.ImporterEdge{
				ImporterName:    name,
				ImporterVersion: ver,
			})
		}
	}

	return edges
}

// edgeDedupKey produces a comparable key for deduplicating edges.
func edgeDedupKey(e pkgmgr.ImporterEdge) string {
	if e.IsWorkspace {
		return "ws:" + e.ImporterName
	}
	return "snap:" + e.ImporterName + "@" + e.ImporterVersion
}

// peerContext is one (name, version) tuple extracted from a snapshot
// key's peer-context suffix.
type peerContext struct {
	Name    string
	Version string
}

// parsePeerContext returns the depth-1 peer-context tuples encoded
// in a pnpm snapshot key. For "react-dom@19.2.6(react@19.2.6)" it
// returns [{react, 19.2.6}]. Nested tuples — peers of peers — are
// intentionally skipped because they're not direct dependencies of
// the outer package.
func parsePeerContext(key string) []peerContext {
	var out []peerContext
	depth := 0
	start := -1
	for i := 0; i < len(key); i++ {
		switch key[i] {
		case '(':
			if depth == 0 {
				start = i + 1
			}
			depth++
		case ')':
			depth--
			if depth == 0 && start >= 0 {
				segment := key[start:i]
				// Inside this top-level group, take only up to the
				// first '(' — anything past that is a nested peer.
				if cut := strings.IndexByte(segment, '('); cut >= 0 {
					segment = segment[:cut]
				}
				if name, ver := splitNameVersion(segment); name != "" {
					out = append(out, peerContext{Name: name, Version: ver})
				}
				start = -1
			}
			if depth < 0 {
				return out // malformed key, bail
			}
		}
	}
	return out
}

// splitNameVersion splits "pkg@1.2.3" or "@scope/pkg@1.2.3" into
// (name, version). The version separator is the last '@', so the
// leading '@' of scoped packages is preserved.
func splitNameVersion(s string) (name, version string) {
	idx := strings.LastIndexByte(s, '@')
	if idx <= 0 {
		return "", ""
	}
	return s[:idx], s[idx+1:]
}

// BareVersion strips a pnpm peer-dependency suffix from a resolved
// version string. pnpm encodes peer context as "1.2.3(peer@4.5.6)";
// for resolution-graph analysis we only want the leading semver.
func BareVersion(v string) string {
	if i := strings.IndexByte(v, '('); i >= 0 {
		return strings.TrimSpace(v[:i])
	}
	return v
}

// splitSnapshotKey splits a snapshot key like "request@2.88.2" or
// "@babel/core@7.29.0(react@19.2.6)" into (name, bareVersion).
// Returns ("", "") if the key isn't in the expected shape, or if the
// version side is a workspace link (which we never bypass-cooldown).
func splitSnapshotKey(k string) (string, string) {
	// Strip any peer-dep suffix first.
	bare := BareVersion(k)
	// The version separator is the last '@' that isn't the leading
	// scope marker.
	idx := strings.LastIndexByte(bare, '@')
	if idx <= 0 {
		return "", ""
	}
	name := bare[:idx]
	ver := bare[idx+1:]
	if strings.HasPrefix(ver, "link:") || strings.HasPrefix(ver, "file:") {
		return "", ""
	}
	return name, ver
}
