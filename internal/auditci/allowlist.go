// Package auditci reads repository-wide audit-ci advisory allowlists.
package auditci

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/robertkasza/deps/internal/pkgmgr"
	"github.com/tidwall/pretty"
)

// Allowlist matches exact GHSA IDs. Its zero value allows no advisories;
// after Load it is immutable and safe to share across workspace audits.
type Allowlist struct {
	ids map[string]struct{}
}

// Load reads audit-ci.json and audit-ci.jsonc at the discovered repository
// root once, combining their allowlists if both exist. Missing files are
// normal; unreadable or unsupported configurations are errors. Other audit-ci
// settings (including severity thresholds) do not affect deps.
func Load(root string) (Allowlist, error) {
	allowed := Allowlist{ids: make(map[string]struct{})}
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
		ids, err := parse(data)
		if err != nil {
			return Allowlist{}, fmt.Errorf("parse %s: %w", path, err)
		}
		for _, id := range ids {
			allowed.ids[id] = struct{}{}
		}
	}
	return allowed, nil
}

var ghsaID = regexp.MustCompile(`^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$`)

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
	var ids []string
	if err := json.Unmarshal(config.Allowlist, &ids); err != nil || ids == nil {
		return nil, fmt.Errorf("allowlist must be an array of GHSA advisory ID strings")
	}
	for i, id := range ids {
		// Package names, wildcard/path rules, numeric IDs, and object-form
		// exceptions are deliberately unsupported rather than broadening an
		// advisory-level exception into a package-level one.
		if !ghsaID.MatchString(id) {
			return nil, fmt.Errorf("allowlist[%d]: only exact GHSA advisory ID strings are supported", i)
		}
	}
	return ids, nil
}

// Filter removes allowlisted advisories before triage and planning, preserving
// the order and contents of the input. Skipped counts advisory findings, which
// may include multiple dependency paths for the same GHSA.
func (a Allowlist) Filter(advisories []pkgmgr.Advisory) (kept []pkgmgr.Advisory, skipped int) {
	if len(a.ids) == 0 {
		return advisories, 0
	}
	kept = make([]pkgmgr.Advisory, 0, len(advisories))
	for _, advisory := range advisories {
		if _, ok := a.ids[advisory.GHSA]; ok {
			skipped++
			continue
		}
		kept = append(kept, advisory)
	}
	return kept, skipped
}
