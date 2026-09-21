package checkcmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/robertkasza/deps/internal/pnpm"
	"github.com/robertkasza/deps/internal/registry"
)

func TestRunAllowlist(t *testing.T) {
	const accepted = `{"allowlist":["GHSA-xxxx-yyyy-zzzz"]}`
	const allAccepted = `{"allowlist":["GHSA-xxxx-yyyy-zzzz","GHSA-aaaa-bbbb-cccc"]}`
	audit, err := os.ReadFile("../pnpm/testdata/audit_allowlist.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, config       string
		monorepo, member   bool
		wantCode, wantRows int
	}{
		{name: "standalone all accepted", config: allAccepted, wantRows: 1},
		{name: "root all accepted", config: allAccepted, monorepo: true, wantRows: 2},
		{name: "member all accepted", config: allAccepted, monorepo: true, member: true, wantRows: 1},
		{name: "member mixed", config: accepted, monorepo: true, member: true, wantCode: 10, wantRows: 1},
		{name: "root concurrent mixed", config: accepted, monorepo: true, wantCode: 10, wantRows: 2},
		{name: "workspace config ignored", monorepo: true, member: true, wantCode: 10, wantRows: 1},
		{name: "invalid root config", config: `{"allowlist":true}`, monorepo: true, member: true, wantCode: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeAllowlistFile(t, root, "package.json", `{"dependencies":{"shared":"^1.0.0"}}`)
			dir := root
			if tc.monorepo {
				writeAllowlistFile(t, root, "pnpm-workspace.yaml", "packages: ['apps/*']\nminimumReleaseAge: 0\n")
				writeAllowlistFile(t, root, "apps/web/package.json", `{"dependencies":{"shared":"^1.0.0"}}`)
				// The member file must not suppress the active advisory.
				writeAllowlistFile(t, root, "apps/web/audit-ci.json", allAccepted)
				if tc.member {
					dir = filepath.Join(root, "apps/web")
				}
			}
			if tc.config != "" {
				writeAllowlistFile(t, root, "audit-ci.json", tc.config)
			}
			var audits atomic.Int32
			pm := pnpm.New().WithRunner(func(dir, name string, args ...string) ([]byte, []byte, int, error) {
				switch strings.Join(args, " ") {
				case "--version":
					return []byte("10.0.0"), nil, 0, nil
				case "audit --json":
					audits.Add(1)
					return audit, nil, 1, nil
				default:
					return nil, nil, -1, fmt.Errorf("unexpected command: %s %v", name, args)
				}
			})
			var stdout, stderr bytes.Buffer
			err := run(Options{Dir: dir, JSON: true, Severity: "low", Concurrency: 3}, &stdout, &stderr, pm, allowlistRegistry{})
			code := 0
			if err != nil {
				code = 1
				if coded, ok := err.(interface{ Code() int }); ok {
					code = coded.Code()
				}
			}
			if code != tc.wantCode {
				t.Fatalf("exit = %d (%v), want %d; stderr: %s", code, err, tc.wantCode, &stderr)
			}
			if code == 1 {
				if audits.Load() != 0 || !strings.Contains(err.Error(), filepath.Join(root, "audit-ci.json")) {
					t.Fatalf("config error should precede auditing: %v (%d audits)", err, audits.Load())
				}
				return
			}
			var out jsonOutput
			if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
				t.Fatalf("stdout is not clean JSON: %v: %s", err, &stdout)
			}
			if out.Root != root || len(out.Workspaces) != tc.wantRows || int(audits.Load()) != tc.wantRows {
				t.Fatalf("wrong scope: %+v (%d audits)", out, audits.Load())
			}
			if tc.config != "" && strings.Contains(stdout.String(), "GHSA-xxxx-yyyy-zzzz") {
				t.Fatalf("allowlisted GHSA leaked into JSON: %s", &stdout)
			}
			if (tc.config != "") != strings.Contains(stderr.String(), "skipped (allowlisted)") {
				t.Fatalf("incorrect skipped output: %s", &stderr)
			}
			for _, ws := range out.Workspaces {
				if tc.config == allAccepted {
					if len(ws.Actionable) != 0 || len(ws.Unresolved) != 0 {
						t.Fatalf("allowlisted workspace is not clean: %+v", ws)
					}
					continue
				}
				if len(ws.Actionable) != 1 || ws.Actionable[0].To != "^1.0.1" {
					t.Fatalf("expected only the active advisory's bump: %+v", ws)
				}
				wantUnresolved := 0
				if tc.config == "" {
					wantUnresolved = 1
				}
				if len(ws.Unresolved) != wantUnresolved {
					t.Fatalf("unresolved = %+v, want %d", ws.Unresolved, wantUnresolved)
				}
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
