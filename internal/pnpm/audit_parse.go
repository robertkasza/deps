package pnpm

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/robertkasza/deps/internal/pkgmgr"
)

// auditOutput is the subset of `pnpm audit --json` we read.
//
// pnpm's audit JSON is documented to be npm-compatible. The fields we
// rely on are stable across recent pnpm versions; new fields are
// ignored. Only the `advisories` map is required.
type auditOutput struct {
	Advisories map[string]auditAdvisory `json:"advisories"`
}

type auditAdvisory struct {
	GitHubAdvisoryID   string         `json:"github_advisory_id"`
	ModuleName         string         `json:"module_name"`
	Severity           string         `json:"severity"`
	VulnerableVersions string         `json:"vulnerable_versions"`
	PatchedVersions    string         `json:"patched_versions"`
	URL                string         `json:"url"`
	Findings           []auditFinding `json:"findings"`
}

type auditFinding struct {
	Version string   `json:"version"`
	Paths   []string `json:"paths"`
}

// parseAudit parses raw pnpm audit JSON and returns advisories
// attributed to ws. Findings whose paths do not originate in ws are
// filtered out.
//
// pnpm encodes the originating workspace as the first path segment with
// slashes replaced by "__" (e.g., workspace "apps/admin" appears in
// paths as "apps__admin>request>tough-cookie"). The root workspace has
// no prefix; its findings have no "__" segment before the first ">".
func parseAudit(data []byte, ws pkgmgr.Workspace) ([]pkgmgr.Advisory, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty audit output")
	}
	var raw auditOutput
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse audit JSON: %w", err)
	}

	wsPrefix := workspacePathPrefix(ws)

	var out []pkgmgr.Advisory
	for _, adv := range raw.Advisories {
		for _, finding := range adv.Findings {
			for _, path := range finding.Paths {
				chain, ok := matchPath(path, wsPrefix, ws.IsRoot)
				if !ok {
					continue
				}
				out = append(out, pkgmgr.Advisory{
					GHSA:            adv.GitHubAdvisoryID,
					Severity:        pkgmgr.Severity(adv.Severity),
					Package:         adv.ModuleName,
					VulnerableRange: adv.VulnerableVersions,
					FixedRange:      adv.PatchedVersions,
					Path:            chain,
					Workspace:       ws,
					URL:             adv.URL,
				})
			}
		}
	}
	return out, nil
}

// workspacePathPrefix encodes a workspace's RelDir into pnpm's audit
// path prefix form ("apps/admin" -> "apps__admin"). Empty for the root.
func workspacePathPrefix(ws pkgmgr.Workspace) string {
	if ws.IsRoot || ws.RelDir == "" {
		return ""
	}
	return strings.ReplaceAll(ws.RelDir, "/", "__")
}

// matchPath returns (chain, true) if path originates in the workspace
// whose prefix is given. chain is the dependency chain after the
// workspace segment, split on ">".
//
// pnpm encodes the originating workspace as the first path segment:
//   - root workspace: "." (e.g., ".>lodash")
//   - other workspaces: dir with slashes replaced by "__"
//     (e.g., "apps__admin>request>tough-cookie")
func matchPath(path, wsPrefix string, isRoot bool) ([]string, bool) {
	if path == "" {
		return nil, false
	}
	segments := strings.Split(path, ">")
	if len(segments) < 2 {
		return nil, false
	}

	expected := wsPrefix
	if isRoot {
		expected = "."
	}
	if segments[0] != expected {
		return nil, false
	}
	return segments[1:], true
}
