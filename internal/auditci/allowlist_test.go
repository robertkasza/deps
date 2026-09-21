package auditci

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/robertkasza/deps/internal/pkgmgr"
)

const (
	allowedGHSA = "GHSA-xxxx-yyyy-zzzz"
	otherGHSA   = "GHSA-aaaa-bbbb-cccc"
)

func TestLoad(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{name: "absent"},
		{name: "no allowlist", files: map[string]string{"audit-ci.json": `{"moderate": true}`}},
		{name: "empty", files: map[string]string{"audit-ci.json": `{"allowlist": []}`}},
		{name: "json", files: map[string]string{"audit-ci.json": `{"allowlist": ["` + allowedGHSA + `"]}`}, want: []string{allowedGHSA}},
		{
			name: "jsonc comments trailing commas and strings",
			files: map[string]string{"audit-ci.jsonc": `{
				// accepted risk
				"$schema": "https://example.com/schema.json",
				"note": "escaped quote: \" // not a comment /* either */",
				"allowlist": [/* rationale */ "` + allowedGHSA + `",],
			}`},
			want: []string{allowedGHSA},
		},
		{
			name: "union and duplicates",
			files: map[string]string{
				"audit-ci.json":  `{"allowlist": ["` + allowedGHSA + `", "` + allowedGHSA + `"]}`,
				"audit-ci.jsonc": `{"allowlist": ["` + allowedGHSA + `", "` + otherGHSA + `"]}`,
			},
			want: []string{allowedGHSA, otherGHSA},
		},
		{name: "workspace file ignored", files: map[string]string{"apps/web/audit-ci.json": `invalid`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for name, content := range tc.files {
				writeFile(t, root, name, content)
			}
			allowed, err := Load(root)
			if err != nil {
				t.Fatal(err)
			}
			if len(allowed.ids) != len(tc.want) {
				t.Fatalf("IDs = %v, want %v", allowed.ids, tc.want)
			}
			for _, id := range tc.want {
				if _, ok := allowed.ids[id]; !ok {
					t.Errorf("missing ID %s", id)
				}
			}
			for name, content := range tc.files {
				data, err := os.ReadFile(filepath.Join(root, name))
				if err != nil || string(data) != content {
					t.Fatalf("config %s changed: %q, %v", name, data, err)
				}
			}
		})
	}
}

func TestLoadInvalid(t *testing.T) {
	for _, name := range []string{"audit-ci.json", "audit-ci.jsonc"} {
		for _, content := range []string{
			``, `null`, `[]`, `true`, `{`, `{} {}`,
			`{"allowlist": null}`, `{"allowlist": "GHSA-xxxx-yyyy-zzzz"}`,
			`{"allowlist": {}}`, `{"allowlist": [1234]}`, `{"allowlist": [null]}`,
			`{"allowlist": [""]}`, `{"allowlist": ["lodash"]}`,
			`{"allowlist": ["GHSA-*"]}`, `{"allowlist": ["GHSA-xxxx-yyyy-zzzz>lodash"]}`,
			`{"allowlist": [{"GHSA-xxxx-yyyy-zzzz": {"expiry": "2030-01-01"}}]}`,
		} {
			t.Run(name+"/"+content, func(t *testing.T) {
				root := t.TempDir()
				writeFile(t, root, name, content)
				_, err := Load(root)
				if err == nil || !strings.Contains(err.Error(), filepath.Join(root, name)) {
					t.Fatalf("want error naming config file, got %v", err)
				}
			})
		}
	}
}

func TestLoadUnreadable(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "audit-ci.json")
	// A directory is unreadable as a file even when tests run as root.
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(root); err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("want read error naming config file, got %v", err)
	}
}

func TestFilter(t *testing.T) {
	allowed := Allowlist{ids: map[string]struct{}{allowedGHSA: {}}}
	input := []pkgmgr.Advisory{
		{GHSA: allowedGHSA, Package: "shared", Path: []string{"parent", "shared"}},
		{GHSA: otherGHSA, Package: "shared"}, // same package, different GHSA survives
		{GHSA: allowedGHSA, Package: "shared", Path: []string{"other-parent", "shared"}},
		{GHSA: "", Package: "unknown"}, // absent IDs must not be suppressed
		{GHSA: allowedGHSA + "-suffix", Package: "shared"},
	}
	original := append([]pkgmgr.Advisory(nil), input...)
	kept, skipped := allowed.Filter(input)
	want := []pkgmgr.Advisory{input[1], input[3], input[4]}
	if skipped != 2 || !reflect.DeepEqual(kept, want) {
		t.Fatalf("Filter = %v, %d; want %v, 2", kept, skipped, want)
	}
	if !reflect.DeepEqual(input, original) {
		t.Fatal("Filter mutated input")
	}
	kept, skipped = (Allowlist{}).Filter(input)
	if skipped != 0 || !reflect.DeepEqual(kept, input) {
		t.Fatal("zero-value allowlist must preserve all advisories")
	}
}

func TestLoadSnapshot(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "audit-ci.json", `{"allowlist": ["`+allowedGHSA+`"]}`)
	allowed, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, root, "audit-ci.json", `{"allowlist": []}`)
	kept, skipped := allowed.Filter([]pkgmgr.Advisory{{GHSA: allowedGHSA}})
	if len(kept) != 0 || skipped != 1 {
		t.Fatal("loaded allowlist must remain stable for the entire command")
	}
}

func writeFile(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
