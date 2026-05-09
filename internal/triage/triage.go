// Package triage classifies an Advisory as direct or transitive for
// its workspace and identifies the top-level parent for transitive
// findings. Pure decision logic — the only I/O is reading each
// workspace's package.json.
package triage

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/robertkasza/deps/internal/pkgmgr"
)

// Run triages a list of advisories. Each unique workspace's
// package.json is read once and cached for the duration of the call.
// Findings are returned in the same order as the input advisories.
func Run(advisories []pkgmgr.Advisory) ([]pkgmgr.Finding, error) {
	cache := map[string]map[string]struct{}{}
	out := make([]pkgmgr.Finding, 0, len(advisories))
	for _, adv := range advisories {
		deps, ok := cache[adv.Workspace.PackageJSON]
		if !ok {
			d, err := readDeclaredDeps(adv.Workspace.PackageJSON)
			if err != nil {
				return nil, err
			}
			deps = d
			cache[adv.Workspace.PackageJSON] = deps
		}
		f, err := triageOne(adv, deps)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// triageOne is the pure classification step: given an advisory and the
// set of names declared in the workspace's package.json (across all
// dep fields), decide direct vs transitive.
func triageOne(adv pkgmgr.Advisory, deps map[string]struct{}) (pkgmgr.Finding, error) {
	if len(adv.Path) == 0 {
		return pkgmgr.Finding{}, fmt.Errorf("advisory %s for %s has empty path",
			adv.GHSA, adv.Package)
	}
	if _, ok := deps[adv.Package]; ok {
		return pkgmgr.Finding{Advisory: adv, Kind: pkgmgr.FindingDirect}, nil
	}
	return pkgmgr.Finding{
		Advisory: adv,
		Kind:     pkgmgr.FindingTransitive,
		Parent:   adv.Path[0],
	}, nil
}

// minimalManifest covers the dep-name fields we care about. Other
// package.json fields are ignored.
type minimalManifest struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

// readDeclaredDeps returns the union of dependency names declared in
// the four standard package.json fields.
func readDeclaredDeps(path string) (map[string]struct{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var m minimalManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	out := map[string]struct{}{}
	for _, m := range []map[string]string{m.Dependencies, m.DevDependencies, m.OptionalDependencies, m.PeerDependencies} {
		for k := range m {
			out[k] = struct{}{}
		}
	}
	return out, nil
}
