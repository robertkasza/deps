package fixcmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/robertkasza/deps/internal/pnpm"
	"github.com/robertkasza/deps/internal/registry"
)

func TestRunAllowlist(t *testing.T) {
	const accepted = `{"allowlist":["GHSA-xxxx-yyyy-zzzz"]}`
	const allAccepted = `{"allowlist":["GHSA-xxxx-yyyy-zzzz","GHSA-aaaa-bbbb-cccc"]}`
	const manifest = `{"dependencies":{"shared":"^1.0.0"}}`
	audit, err := os.ReadFile("../pnpm/testdata/audit_allowlist.json")
	if err != nil {
		t.Fatal(err)
	}
	var after struct {
		Advisories map[string]json.RawMessage `json:"advisories"`
	}
	if err := json.Unmarshal(audit, &after); err != nil {
		t.Fatal(err)
	}
	delete(after.Advisories, "2") // active advisory clears, allowlisted one remains
	onlyAllowlisted, err := json.Marshal(after)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, config string
		member       bool
		stillPresent bool
		wantCode     int
		wantInstall  int
	}{
		{name: "all allowlisted no-op", config: allAccepted},
		{name: "member no-op", config: allAccepted, member: true},
		{name: "mixed verified", config: accepted, wantInstall: 1},
		{name: "member mixed verified", config: accepted, member: true, wantInstall: 1},
		{name: "active advisory remains", config: accepted, stillPresent: true, wantCode: 20, wantInstall: 1},
		{name: "invalid config", config: `{"allowlist": [1234]}`, wantCode: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeAllowlistFile(t, root, "package.json", manifest)
			// Exercise JSONC handling through the command, not just the loader.
			config := "// accepted advisories\n" + tc.config
			writeAllowlistFile(t, root, "audit-ci.jsonc", config)
			dir := root
			if tc.member {
				writeAllowlistFile(t, root, "pnpm-workspace.yaml", "packages: ['apps/*']\nminimumReleaseAge: 0\n")
				writeAllowlistFile(t, root, "apps/web/package.json", manifest)
				// Even a malformed member-local file is not read.
				writeAllowlistFile(t, root, "apps/web/audit-ci.jsonc", "invalid")
				dir = filepath.Join(root, "apps/web")
			}
			writeAllowlistFile(t, root, "pnpm-lock.yaml", "lockfileVersion: '9.0'\n")
			audits, installs := 0, 0
			pm := pnpm.New().WithRunner(func(cwd, name string, args ...string) ([]byte, []byte, int, error) {
				switch strings.Join(args, " ") {
				case "--version":
					return []byte("10.0.0"), nil, 0, nil
				case "audit --json":
					if cwd != dir {
						return nil, nil, -1, fmt.Errorf("wrong audit scope: %s", cwd)
					}
					audits++
					if installs > 0 && !tc.stillPresent {
						return onlyAllowlisted, nil, 1, nil
					}
					return audit, nil, 1, nil
				case "install":
					if cwd != root {
						return nil, nil, -1, fmt.Errorf("install is not at root: %s", cwd)
					}
					installs++
					return nil, nil, 0, nil
				default:
					return nil, nil, -1, fmt.Errorf("unexpected command: %s %v", name, args)
				}
			})
			var stdout, stderr bytes.Buffer
			err := run(Options{Dir: dir, Concurrency: 1}, &stdout, &stderr, pm, allowlistRegistry{})
			code := 0
			if err != nil {
				code = 1
				if coded, ok := err.(interface{ Code() int }); ok {
					code = coded.Code()
				}
			}
			if code != tc.wantCode || installs != tc.wantInstall {
				t.Fatalf("exit/install = %d/%d (%v), want %d/%d; stderr: %s", code, installs, err, tc.wantCode, tc.wantInstall, &stderr)
			}
			wantAudits := 1 + tc.wantInstall
			if tc.wantCode == 1 {
				wantAudits = 0
			}
			if audits != wantAudits {
				t.Fatalf("audits = %d, want %d", audits, wantAudits)
			}
			if tc.wantCode != 1 && strings.Count(stderr.String(), "skipped (allowlisted)") != wantAudits {
				t.Fatalf("each audit should report skipped findings: %s", &stderr)
			}
			if strings.Contains(stderr.String(), "GHSA-xxxx-yyyy-zzzz") {
				t.Fatalf("allowlisted advisory leaked into report: %s", &stderr)
			}
			if tc.wantInstall == 0 {
				assertFile(t, filepath.Join(dir, "package.json"), manifest)
			} else {
				data, err := os.ReadFile(filepath.Join(dir, "package.json"))
				if err != nil || !bytes.Contains(data, []byte(`"^1.0.1"`)) {
					t.Fatalf("expected active advisory's bump only: %s (%v)", data, err)
				}
			}
			assertFile(t, filepath.Join(root, "audit-ci.jsonc"), config)
			assertFile(t, filepath.Join(root, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n")
			if tc.member {
				assertFile(t, filepath.Join(root, "package.json"), manifest)
				assertFile(t, filepath.Join(dir, "audit-ci.jsonc"), "invalid")
			}
		})
	}
}

type allowlistRegistry struct{}

func (allowlistRegistry) Versions(string) ([]string, error) {
	return []string{"1.0.0", "1.0.1", "2.0.0"}, nil
}

func (allowlistRegistry) Manifest(pkg, version string) (registry.Manifest, error) {
	return registry.Manifest{}, fmt.Errorf("unexpected manifest lookup: %s@%s", pkg, version)
}

func writeAllowlistFile(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertFile(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil || string(data) != want {
		t.Fatalf("%s changed: %q (%v); want %q", path, data, err, want)
	}
}
