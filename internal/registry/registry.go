// Package registry queries the npm registry for package metadata
// (versions and per-version dependencies).
//
// MVP: direct HTTP to https://registry.npmjs.org, respecting `registry=`
// in the user's .npmrc. In-process cache for the lifetime of one run.
// No auth handling for private registries yet.
package registry

// Client fetches package metadata from a configured npm registry.
type Client interface {
	// Versions returns all published version strings for pkg, newest-first.
	Versions(pkg string) ([]string, error)

	// Manifest returns the package.json metadata for a specific version
	// (notably, its dependencies map). Used by plan to check whether a
	// candidate parent version pulls in a fixed sub-dep.
	Manifest(pkg, version string) (Manifest, error)
}

// Manifest is a minimal subset of an npm package manifest.
type Manifest struct {
	Name             string
	Version          string
	Dependencies     map[string]string
	PeerDependencies map[string]string
}

// New returns a default registry Client.
//
// TODO: implement HTTP client + .npmrc lookup + in-process cache.
func New() Client {
	return nil
}
