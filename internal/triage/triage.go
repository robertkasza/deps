// Package triage decides whether an advisory is direct or transitive
// for a given workspace and identifies the top-level parent for
// transitive findings. Pure function over advisory + package.json.
package triage

import "github.com/robertkasza/deps/internal/pkgmgr"

// Run triages a list of advisories against their workspaces and produces
// findings ready for the plan stage.
//
// TODO: implement.
func Run(advisories []pkgmgr.Advisory) ([]pkgmgr.Finding, error) {
	return nil, nil
}
