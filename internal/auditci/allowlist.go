// Package auditci reads repository-wide audit-ci advisory allowlists.
package auditci

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/robertkasza/deps/internal/pkgmgr"
	"github.com/tidwall/pretty"
)

// Allowlist matches exact GHSA IDs and audit-ci "GHSA-id|path" entries.
// Its zero value allows no advisories; after Load it is immutable and safe to
// share across workspace audits.
type Allowlist struct {
	ids   map[string]struct{}
	paths map[string][]*regexp.Regexp // GHSA ID -> dependency path patterns
}

// Load reads audit-ci.json and audit-ci.jsonc at the discovered repository
// root once, combining their allowlists if both exist. Missing files are
// normal; unreadable or unsupported configurations are errors. Other audit-ci
// settings (including severity thresholds) do not affect deps.
func Load(root string) (Allowlist, error) {
	allowed := Allowlist{ids: make(map[string]struct{}), paths: make(map[string][]*regexp.Regexp)}
	for _, name := range []string{"audit-ci.json", "audit-ci.jsonc"} {
		path := filepath.Join(root, name)
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return Allowlist{}, fmt.Errorf("read %s: %w", path, err)
		}
		if name == "audit-ci.jsonc" {
			data = pretty.Spec(data)
		}
		entries, err := parse(data)
		if err != nil {
			return Allowlist{}, fmt.Errorf("parse %s: %w", path, err)
		}
		for _, entry := range entries {
			id, pattern, scoped := strings.Cut(entry, "|")
			if !scoped {
				allowed.ids[id] = struct{}{}
				continue
			}
			allowed.paths[id] = append(allowed.paths[id], pathPattern(pattern))
		}
	}
	return allowed, nil
}

var (
	ghsaID    = regexp.MustCompile(`^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$`)
	wildcards = regexp.MustCompile(`\*+`)
)

func parse(data []byte) ([]string, error) {
	var config *struct {
		Allowlist json.RawMessage `json:"allowlist"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	if config == nil {
		return nil, fmt.Errorf("expected a configuration object")
	}
	if len(config.Allowlist) == 0 {
		return nil, nil
	}
	var entries []string
	if err := json.Unmarshal(config.Allowlist, &entries); err != nil || entries == nil {
		return nil, fmt.Errorf("allowlist must be an array of GHSA advisory ID or GHSA|path strings")
	}
	for i, entry := range entries {
		// Package names, numeric IDs, wildcard advisory IDs, and object-form
		// exceptions are deliberately unsupported rather than broadening an
		// advisory-level exception into a package-level one.
		id, pattern, scoped := strings.Cut(entry, "|")
		if !ghsaID.MatchString(id) || (scoped && pattern == "") {
			return nil, fmt.Errorf("allowlist[%d]: only exact GHSA advisory IDs, optionally scoped as GHSA|path, are supported", i)
		}
	}
	return entries, nil
}

// pathPattern compiles an audit-ci dependency path pattern. As in audit-ci,
// each run of "*" matches any characters (including ">") and the pattern must
// match the whole path; a pattern without "*" is an exact match.
func pathPattern(pattern string) *regexp.Regexp {
	parts := wildcards.Split(pattern, -1)
	for i, part := range parts {
		parts[i] = regexp.QuoteMeta(part)
	}
	return regexp.MustCompile("^" + strings.Join(parts, ".*") + "$")
}

// auditCIPath returns a finding's dependency path as audit-ci sees it. audit-ci
// strips pnpm's leading ".>" (for the audited importer) before matching; other
// segments, such as hoisted-mode workspace prefixes, are kept.
func auditCIPath(advisory pkgmgr.Advisory) string {
	if advisory.AuditPath == "" {
		return strings.Join(advisory.Path, ">")
	}
	return strings.TrimPrefix(advisory.AuditPath, ".>")
}

func (a Allowlist) allows(advisory pkgmgr.Advisory) bool {
	if _, ok := a.ids[advisory.GHSA]; ok {
		return true
	}
	patterns := a.paths[advisory.GHSA]
	if len(patterns) == 0 {
		return false
	}
	path := auditCIPath(advisory)
	for _, pattern := range patterns {
		if pattern.MatchString(path) {
			return true
		}
	}
	return false
}

// Filter removes allowlisted advisories before triage and planning, preserving
// the order and contents of the input. Skipped holds the removed advisory
// findings, which may include multiple dependency paths for the same GHSA;
// planning uses them to avoid repo-wide edits that would change them.
func (a Allowlist) Filter(advisories []pkgmgr.Advisory) (kept, skipped []pkgmgr.Advisory) {
	if len(a.ids) == 0 && len(a.paths) == 0 {
		return advisories, nil
	}
	kept = make([]pkgmgr.Advisory, 0, len(advisories))
	for _, advisory := range advisories {
		if a.allows(advisory) {
			skipped = append(skipped, advisory)
			continue
		}
		kept = append(kept, advisory)
	}
	return kept, skipped
}
