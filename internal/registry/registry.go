// Package registry queries the npm registry for package metadata
// (versions and per-version dependencies). Respects `registry=` in .npmrc.
// Caches responses in-process for the duration of a run.
package registry

// TODO: implement Client with Versions(pkg string) and Manifest(pkg, version string).
