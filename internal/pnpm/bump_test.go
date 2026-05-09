package pnpm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestWriteBump_Basic(t *testing.T) {
	dir := t.TempDir()
	pj := writeFile(t, dir, "package.json", `{
  "name": "demo",
  "dependencies": {
    "lodash": "^4.17.20",
    "axios": "^1.0.0"
  }
}
`)
	if err := writeBump(pj, "dependencies", "lodash", "^4.17.21"); err != nil {
		t.Fatalf("writeBump: %v", err)
	}
	got, _ := os.ReadFile(pj)
	want := `{
  "name": "demo",
  "dependencies": {
    "lodash": "^4.17.21",
    "axios": "^1.0.0"
  }
}
`
	if string(got) != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestWriteBump_DevDependencies(t *testing.T) {
	dir := t.TempDir()
	pj := writeFile(t, dir, "package.json", `{
  "devDependencies": {
    "minimist": "1.2.0"
  }
}
`)
	if err := writeBump(pj, "devDependencies", "minimist", "1.2.6"); err != nil {
		t.Fatalf("writeBump: %v", err)
	}
	got, _ := os.ReadFile(pj)
	if !strings.Contains(string(got), `"minimist": "1.2.6"`) {
		t.Errorf("missing bumped version: %s", got)
	}
}

func TestWriteBump_ScopedPackage(t *testing.T) {
	dir := t.TempDir()
	pj := writeFile(t, dir, "package.json", `{
  "dependencies": {
    "@scope/name": "1.0.0"
  }
}
`)
	if err := writeBump(pj, "dependencies", "@scope/name", "1.0.1"); err != nil {
		t.Fatalf("writeBump: %v", err)
	}
	got, _ := os.ReadFile(pj)
	if !strings.Contains(string(got), `"@scope/name": "1.0.1"`) {
		t.Errorf("scoped bump: %s", got)
	}
}

func TestWriteBump_MissingPackage(t *testing.T) {
	dir := t.TempDir()
	pj := writeFile(t, dir, "package.json", `{"dependencies": {"lodash": "^4"}}`)
	err := writeBump(pj, "dependencies", "axios", "^1.0.0")
	if err == nil {
		t.Errorf("expected error for missing package")
	}
}

func TestWriteBump_PreservesKeyOrder(t *testing.T) {
	dir := t.TempDir()
	pj := writeFile(t, dir, "package.json", `{
  "name": "demo",
  "version": "1.0.0",
  "dependencies": {
    "z-package": "1.0.0",
    "a-package": "2.0.0",
    "m-package": "3.0.0"
  },
  "scripts": {
    "build": "tsc"
  }
}
`)
	if err := writeBump(pj, "dependencies", "a-package", "2.0.1"); err != nil {
		t.Fatalf("writeBump: %v", err)
	}
	got, _ := os.ReadFile(pj)
	// Verify the order z-package, a-package, m-package is preserved.
	zIdx := strings.Index(string(got), "z-package")
	aIdx := strings.Index(string(got), "a-package")
	mIdx := strings.Index(string(got), "m-package")
	if !(zIdx < aIdx && aIdx < mIdx) {
		t.Errorf("key order not preserved: %s", got)
	}
	// And the fields outside dependencies are untouched.
	if !strings.Contains(string(got), `"name": "demo"`) ||
		!strings.Contains(string(got), `"build": "tsc"`) {
		t.Errorf("surrounding fields modified: %s", got)
	}
}

func TestWriteBump_PreservesIndentAndTrailingNewline(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"2-space indent + trailing newline", "{\n  \"dependencies\": {\n    \"x\": \"1.0.0\"\n  }\n}\n"},
		{"4-space indent + trailing newline", "{\n    \"dependencies\": {\n        \"x\": \"1.0.0\"\n    }\n}\n"},
		{"tab indent + no trailing newline", "{\n\t\"dependencies\": {\n\t\t\"x\": \"1.0.0\"\n\t}\n}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			pj := writeFile(t, dir, "package.json", tc.content)
			if err := writeBump(pj, "dependencies", "x", "1.0.1"); err != nil {
				t.Fatalf("writeBump: %v", err)
			}
			got, _ := os.ReadFile(pj)
			// Trailing newline preserved.
			origHadNewline := strings.HasSuffix(tc.content, "\n")
			gotHasNewline := strings.HasSuffix(string(got), "\n")
			if origHadNewline != gotHasNewline {
				t.Errorf("trailing newline changed: orig=%v got=%v\n%s", origHadNewline, gotHasNewline, got)
			}
		})
	}
}
