package plan

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/robertkasza/deps/internal/pkgmgr"
)

// pkgFields is the subset of package.json plan reads.
type pkgFields struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

// depFieldName names the dependency map a package appears in.
type depFieldName string

const (
	fieldDependencies         depFieldName = "dependencies"
	fieldDevDependencies      depFieldName = "devDependencies"
	fieldOptionalDependencies depFieldName = "optionalDependencies"
	fieldPeerDependencies     depFieldName = "peerDependencies"
)

// readManifest parses a workspace package.json into pkgFields.
func readManifest(path string) (pkgFields, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return pkgFields{}, fmt.Errorf("read %s: %w", path, err)
	}
	var p pkgFields
	if err := json.Unmarshal(data, &p); err != nil {
		return pkgFields{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return p, nil
}

// findDep returns the constraint and field where pkg appears in m.
// Found is false if pkg is in none of the dep fields.
func (m pkgFields) findDep(pkg string) (constraint string, field depFieldName, found bool) {
	for _, pair := range []struct {
		field depFieldName
		m     map[string]string
	}{
		{fieldDependencies, m.Dependencies},
		{fieldDevDependencies, m.DevDependencies},
		{fieldOptionalDependencies, m.OptionalDependencies},
		{fieldPeerDependencies, m.PeerDependencies},
	} {
		if v, ok := pair.m[pkg]; ok {
			return v, pair.field, true
		}
	}
	return "", "", false
}

// manifestCache is a per-Build cache: workspace package.json path -> parsed fields.
type manifestCache map[string]pkgFields

func (c manifestCache) get(ws pkgmgr.Workspace) (pkgFields, error) {
	if m, ok := c[ws.PackageJSON]; ok {
		return m, nil
	}
	m, err := readManifest(ws.PackageJSON)
	if err != nil {
		return pkgFields{}, err
	}
	c[ws.PackageJSON] = m
	return m, nil
}
