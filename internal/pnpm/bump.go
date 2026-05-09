package pnpm

import (
	"fmt"
	"os"
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// writeBump updates a single dependency version in a workspace's
// package.json. The file is read, the value at <field>.<pkg> is
// replaced with version, and the file is rewritten preserving original
// formatting (key order, indent, trailing newline). field is one of
// "dependencies", "devDependencies", "optionalDependencies",
// "peerDependencies".
//
// Returns an error if <field>.<pkg> doesn't exist.
func writeBump(file, field, pkg, version string) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("read %s: %w", file, err)
	}

	path := field + "." + escapePathSegment(pkg)
	if !gjson.GetBytes(data, path).Exists() {
		return fmt.Errorf("%s: %s.%s not found", file, field, pkg)
	}

	out, err := sjson.SetBytes(data, path, version)
	if err != nil {
		return fmt.Errorf("set %s in %s: %w", path, file, err)
	}

	if err := os.WriteFile(file, out, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", file, err)
	}
	return nil
}

// escapePathSegment escapes characters with special meaning in
// gjson/sjson path syntax. Per gjson docs: ".", "*", "?", "#", "@",
// "\\". Override keys like "qs@<6.14.1" need both "@" and "."
// escaped; scoped package names like "@scope/name" need "@" escaped.
func escapePathSegment(s string) string {
	if !strings.ContainsAny(s, ".*?#@\\") {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '.', '*', '?', '#', '@', '\\':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}
