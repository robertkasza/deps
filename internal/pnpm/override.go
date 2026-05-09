package pnpm

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/pretty"
	"github.com/tidwall/sjson"
	"gopkg.in/yaml.v3"
)

// writeOverride adds a pnpm override entry to the appropriate file in
// the monorepo rooted at root.
//
// Target file selection:
//  1. If pnpm-workspace.yaml has an `overrides:` mapping (even empty),
//     write there.
//  2. Else if root package.json has `pnpm.overrides`, write there.
//  3. Else create the entry in root package.json's `pnpm.overrides`
//     (matches what `pnpm audit --fix` produces).
//
// The key is `<pkg>@<vulnRange>`, the value is fixedRange. Existing
// keys for the same package are not consolidated for MVP — the caller
// is expected to dedupe edits before reaching here.
func writeOverride(root, pkg, vulnRange, fixedRange string) (file string, err error) {
	key := pkg + "@" + vulnRange

	yamlPath := filepath.Join(root, "pnpm-workspace.yaml")
	pkgPath := filepath.Join(root, "package.json")

	if hasYAMLOverrides(yamlPath) {
		if err := writeYAMLOverride(yamlPath, key, fixedRange); err != nil {
			return "", err
		}
		return yamlPath, nil
	}
	if hasPkgJSONOverrides(pkgPath) {
		if err := writePkgJSONOverride(pkgPath, key, fixedRange); err != nil {
			return "", err
		}
		return pkgPath, nil
	}
	// Default: create in root package.json.
	if err := writePkgJSONOverride(pkgPath, key, fixedRange); err != nil {
		return "", err
	}
	return pkgPath, nil
}

// hasYAMLOverrides reports whether pnpm-workspace.yaml exists and has
// an `overrides:` key (regardless of whether it's empty).
func hasYAMLOverrides(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var m map[string]any
	if err := yaml.Unmarshal(data, &m); err != nil {
		return false
	}
	_, ok := m["overrides"]
	return ok
}

// hasPkgJSONOverrides reports whether package.json has `pnpm.overrides`.
func hasPkgJSONOverrides(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return gjson.GetBytes(data, "pnpm.overrides").Exists()
}

// writePkgJSONOverride sets pnpm.overrides[key] = value in
// the package.json at path, preserving formatting elsewhere.
//
// When the key already exists, sjson preserves byte-level formatting.
// When sjson has to create a new nested key (e.g., adding pnpm.overrides
// to a file that doesn't have one), it appends in compact form; we
// detect that and re-pretty-format to keep the diff readable.
func writePkgJSONOverride(path, key, value string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s does not exist", path)
		}
		return fmt.Errorf("read %s: %w", path, err)
	}
	hadKey := gjson.GetBytes(data, "pnpm.overrides."+escapePathSegment(key)).Exists()
	sjsonPath := "pnpm.overrides." + escapePathSegment(key)
	out, err := sjson.SetBytes(data, sjsonPath, value)
	if err != nil {
		return fmt.Errorf("set %s in %s: %w", sjsonPath, path, err)
	}
	if !hadKey {
		out = pretty.PrettyOptions(out, &pretty.Options{
			Indent: detectJSONIndent(data),
			Width:  0,
		})
		// Pretty drops the trailing newline; restore if the source had one.
		if bytes.HasSuffix(data, []byte("\n")) && !bytes.HasSuffix(out, []byte("\n")) {
			out = append(out, '\n')
		}
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// detectJSONIndent reads the first nested-line indent from the file
// (the whitespace before the first key inside the top-level object).
// Defaults to 2 spaces.
func detectJSONIndent(data []byte) string {
	s := string(data)
	if i := strings.Index(s, "{"); i >= 0 {
		// Scan past `{` to next non-newline char that starts a key.
		for j := i + 1; j < len(s); j++ {
			if s[j] == '\n' {
				k := j + 1
				for k < len(s) && (s[k] == ' ' || s[k] == '\t') {
					k++
				}
				if k > j+1 {
					return s[j+1 : k]
				}
				break
			}
		}
	}
	return "  "
}

// writeYAMLOverride sets overrides[key] = value in pnpm-workspace.yaml.
// Uses yaml.v3's Node API to preserve comments and surrounding format.
func writeYAMLOverride(path, key, value string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return fmt.Errorf("%s: unexpected YAML structure", path)
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return fmt.Errorf("%s: top-level is not a mapping", path)
	}

	// Find or create the overrides mapping.
	var overrides *yaml.Node
	for i := 0; i < len(root.Content)-1; i += 2 {
		k := root.Content[i]
		if k.Kind == yaml.ScalarNode && k.Value == "overrides" {
			overrides = root.Content[i+1]
			break
		}
	}
	if overrides == nil {
		root.Content = append(root.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: "overrides"},
			&yaml.Node{Kind: yaml.MappingNode},
		)
		overrides = root.Content[len(root.Content)-1]
	}
	if overrides.Kind != yaml.MappingNode {
		return fmt.Errorf("%s: overrides is not a mapping", path)
	}

	// Replace existing key or append a new pair.
	for i := 0; i < len(overrides.Content)-1; i += 2 {
		k := overrides.Content[i]
		if k.Kind == yaml.ScalarNode && k.Value == key {
			overrides.Content[i+1] = newScalar(value)
			return writeYAML(path, &doc)
		}
	}
	overrides.Content = append(overrides.Content,
		newScalar(key),
		newScalar(value),
	)
	return writeYAML(path, &doc)
}

func newScalar(v string) *yaml.Node {
	// Quote values that aren't safely bare. Override keys contain "@"
	// and ranges contain "<", ">", " " — all need quoting in YAML.
	return &yaml.Node{Kind: yaml.ScalarNode, Style: yaml.DoubleQuotedStyle, Value: v}
}

func writeYAML(path string, doc *yaml.Node) error {
	out, err := yaml.Marshal(doc)
	if err != nil {
		return fmt.Errorf("marshal %s: %w", path, err)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
