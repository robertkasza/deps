package pnpm

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// writeCooldownExclude appends an exact-version entry (pkg@version)
// to minimumReleaseAgeExclude in pnpm-workspace.yaml at root. The list
// is created if it doesn't exist; the workspace yaml itself is created
// if it doesn't exist. Idempotent — duplicate entries are skipped.
//
// Exact-version form (pkg@version) is always used, never a bare name
// or a range. This keeps the cooldown bypass narrowly scoped to a
// single reviewed version, so a hypothetical future malicious publish
// of the same package still goes through the normal cooldown soak.
func writeCooldownExclude(root, pkg, version string) (file string, err error) {
	path := filepath.Join(root, "pnpm-workspace.yaml")
	entry := pkg + "@" + version

	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("read %s: %w", path, err)
	}

	var doc yaml.Node
	if len(data) > 0 {
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return "", fmt.Errorf("parse %s: %w", path, err)
		}
	}
	if doc.Kind == 0 {
		// Empty or missing — start a fresh document.
		doc = yaml.Node{
			Kind: yaml.DocumentNode,
			Content: []*yaml.Node{{
				Kind: yaml.MappingNode,
			}},
		}
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return "", fmt.Errorf("%s: unexpected YAML structure", path)
	}
	root_ := doc.Content[0]
	if root_.Kind != yaml.MappingNode {
		return "", fmt.Errorf("%s: top-level is not a mapping", path)
	}

	var list *yaml.Node
	for i := 0; i < len(root_.Content)-1; i += 2 {
		k := root_.Content[i]
		if k.Kind == yaml.ScalarNode && k.Value == "minimumReleaseAgeExclude" {
			list = root_.Content[i+1]
			break
		}
	}
	if list == nil {
		root_.Content = append(root_.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: "minimumReleaseAgeExclude"},
			&yaml.Node{Kind: yaml.SequenceNode},
		)
		list = root_.Content[len(root_.Content)-1]
	}
	if list.Kind != yaml.SequenceNode {
		return "", fmt.Errorf("%s: minimumReleaseAgeExclude is not a sequence", path)
	}

	for _, item := range list.Content {
		if item.Kind == yaml.ScalarNode && item.Value == entry {
			// Already present — no write needed, but report the file
			// so the caller can record it.
			return path, nil
		}
	}
	list.Content = append(list.Content, &yaml.Node{
		Kind:  yaml.ScalarNode,
		Style: yaml.DoubleQuotedStyle,
		Value: entry,
	})

	if err := writeYAMLPreserve(path, &doc, data); err != nil {
		return "", err
	}
	return path, nil
}

// writeYAMLPreserve is writeYAML adapted for the case where the source
// file might not exist yet. It uses the existing reinjectBlankLines /
// detectYAMLIndent helpers from override.go when source bytes are
// available; for a fresh file, it falls back to default formatting.
func writeYAMLPreserve(path string, doc *yaml.Node, src []byte) error {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	if len(src) > 0 {
		enc.SetIndent(detectYAMLIndent(src))
	} else {
		enc.SetIndent(2)
	}
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("marshal %s: %w", path, err)
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("marshal %s: %w", path, err)
	}
	out := buf.Bytes()
	if len(src) > 0 {
		out = reinjectBlankLines(src, out)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
