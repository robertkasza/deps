package pnpm

import (
	"path/filepath"
	"sort"
	"testing"
)

func TestBareVersion(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"1.2.3", "1.2.3"},
		{"19.2.6(react@19.2.6)", "19.2.6"},
		{"6.0.1(vite@8.0.11(@types/node@24.12.3))", "6.0.1"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := BareVersion(tt.in); got != tt.want {
			t.Errorf("BareVersion(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSplitSnapshotKey(t *testing.T) {
	tests := []struct {
		in, wantName, wantVer string
	}{
		{"request@2.88.2", "request", "2.88.2"},
		{"@babel/core@7.29.0", "@babel/core", "7.29.0"},
		{"react-dom@19.2.6(react@19.2.6)", "react-dom", "19.2.6"},
		{"@types/react-dom@19.2.3(@types/react@19.2.14)", "@types/react-dom", "19.2.3"},
		{"foo@link:../bar", "", ""},
		{"malformed", "", ""},
	}
	for _, tt := range tests {
		gotName, gotVer := splitSnapshotKey(tt.in)
		if gotName != tt.wantName || gotVer != tt.wantVer {
			t.Errorf("splitSnapshotKey(%q) = (%q, %q), want (%q, %q)",
				tt.in, gotName, gotVer, tt.wantName, tt.wantVer)
		}
	}
}

func TestParseLockfile_VulnTest(t *testing.T) {
	// Real lockfile fixture from the playground monorepo.
	path := filepath.Join("..", "..", "playground", "vuln-test", "pnpm-lock.yaml")
	lf, err := ParseLockfile(path)
	if err != nil {
		t.Fatalf("ParseLockfile: %v", err)
	}
	if lf.Version == "" || lf.Version[:2] != "9." {
		t.Errorf("unexpected lockfileVersion %q", lf.Version)
	}
	if _, ok := lf.Importers["apps/admin"]; !ok {
		t.Errorf("missing apps/admin importer")
	}
	if _, ok := lf.Snapshots["request@2.88.2"]; !ok {
		t.Errorf("missing request@2.88.2 snapshot")
	}
}

func TestImportersOf_WorkspaceDirect(t *testing.T) {
	path := filepath.Join("..", "..", "playground", "vuln-test", "pnpm-lock.yaml")
	lf, err := ParseLockfile(path)
	if err != nil {
		t.Fatalf("ParseLockfile: %v", err)
	}
	// request@2.88.2 is declared directly in apps/admin's dependencies.
	edges := lf.ImportersOf("request", "2.88.2")
	if len(edges) == 0 {
		t.Fatalf("expected at least one importer for request@2.88.2")
	}
	var foundWS bool
	for _, e := range edges {
		if e.IsWorkspace && e.ImporterName == "apps/admin" {
			foundWS = true
			if e.DeclaredRange != "2.88.2" {
				t.Errorf("apps/admin declared range = %q, want %q", e.DeclaredRange, "2.88.2")
			}
		}
	}
	if !foundWS {
		t.Errorf("did not find apps/admin as a workspace importer")
	}
}

func TestImportersOf_Transitive(t *testing.T) {
	path := filepath.Join("..", "..", "playground", "vuln-test", "pnpm-lock.yaml")
	lf, err := ParseLockfile(path)
	if err != nil {
		t.Fatalf("ParseLockfile: %v", err)
	}
	// tough-cookie@2.5.0 is a transitive of request@2.88.2.
	edges := lf.ImportersOf("tough-cookie", "2.5.0")
	if len(edges) == 0 {
		t.Fatalf("expected at least one importer for tough-cookie@2.5.0")
	}
	var foundRequest bool
	for _, e := range edges {
		if !e.IsWorkspace && e.ImporterName == "request" && e.ImporterVersion == "2.88.2" {
			foundRequest = true
			if e.DeclaredRange != "" {
				t.Errorf("transitive edge should have empty DeclaredRange, got %q", e.DeclaredRange)
			}
		}
	}
	if !foundRequest {
		var names []string
		for _, e := range edges {
			names = append(names, e.ImporterName+"@"+e.ImporterVersion)
		}
		sort.Strings(names)
		t.Errorf("did not find request@2.88.2 as importer of tough-cookie@2.5.0; got %v", names)
	}
}

func TestParsePeerContext(t *testing.T) {
	tests := []struct {
		key  string
		want []peerContext
	}{
		{"react-dom@19.2.6", nil},
		{"react-dom@19.2.6(react@19.2.6)", []peerContext{{"react", "19.2.6"}}},
		{
			"@expo/vector-icons@13.0.0(react@18.2.0)(react-native@0.73.0)(ws@8.12.1)",
			[]peerContext{
				{"react", "18.2.0"},
				{"react-native", "0.73.0"},
				{"ws", "8.12.1"},
			},
		},
		// Nested: only outer depth-1 tuple counted.
		{
			"react-dom@19.2.6(react@19.2.6(react-native@0.73.0))",
			[]peerContext{{"react", "19.2.6"}},
		},
		{"@types/react-dom@19.2.3(@types/react@19.2.14)", []peerContext{{"@types/react", "19.2.14"}}},
	}
	for _, tt := range tests {
		got := parsePeerContext(tt.key)
		if len(got) != len(tt.want) {
			t.Errorf("parsePeerContext(%q): got %v, want %v", tt.key, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("parsePeerContext(%q)[%d]: got %v, want %v", tt.key, i, got[i], tt.want[i])
			}
		}
	}
}

func TestImportersOf_PeerContextOnly(t *testing.T) {
	// Synthetic lockfile fragment: A@1 lists B@2 only in its peer
	// suffix, never in its dependencies block. Without peer-context
	// extraction, ImportersOf("B", "2") returns 0; with it, returns 1.
	lf := &Lockfile{
		Version:   "9.0",
		Importers: map[string]Importer{},
		Snapshots: map[string]Snapshot{
			"A@1(B@2)": {
				Dependencies: map[string]string{},
			},
		},
	}
	edges := lf.ImportersOf("B", "2")
	if len(edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(edges))
	}
	if edges[0].ImporterName != "A" || edges[0].ImporterVersion != "1" {
		t.Errorf("unexpected edge: %+v", edges[0])
	}
}

func TestImportersOf_NoDoubleCountAcrossDepsAndPeerContext(t *testing.T) {
	// When a peer appears both in the dependencies block AND in the
	// snapshot key suffix (the common case for autoInstallPeers=true),
	// the edge must not be duplicated.
	lf := &Lockfile{
		Version:   "9.0",
		Importers: map[string]Importer{},
		Snapshots: map[string]Snapshot{
			"A@1(B@2)": {
				Dependencies: map[string]string{"B": "2"},
			},
		},
	}
	edges := lf.ImportersOf("B", "2")
	if len(edges) != 1 {
		t.Errorf("expected 1 deduped edge, got %d: %+v", len(edges), edges)
	}
}

// Reproduces nhost's brace-expansion case: minimatch lists
// brace-expansion as a plain dependency in its snapshot block. The
// parser must find this importer, otherwise cooldown-bypass falsely
// reports "no importers".
func TestImportersOf_BraceExpansionShape(t *testing.T) {
	src := `lockfileVersion: '9.0'

settings:
  autoInstallPeers: true

snapshots:

  mimic-fn@2.1.0: {}

  minimatch@10.2.4:
    dependencies:
      brace-expansion: 5.0.5
`
	tmp := t.TempDir()
	path := tmp + "/pnpm-lock.yaml"
	writeFile(t, tmp, "pnpm-lock.yaml", src)

	lf, err := ParseLockfile(path)
	if err != nil {
		t.Fatalf("ParseLockfile: %v", err)
	}
	t.Logf("snapshots parsed: %d", len(lf.Snapshots))
	for k, s := range lf.Snapshots {
		t.Logf("  snap %q deps=%v", k, s.Dependencies)
	}

	edges := lf.ImportersOfRange("brace-expansion", ">=5.0.0 <5.0.6")
	if len(edges) == 0 {
		t.Fatalf("expected minimatch as importer of brace-expansion@5.0.5; got 0 edges")
	}
	t.Logf("edges: %+v", edges)
}

func TestImportersOf_NoMatch(t *testing.T) {
	path := filepath.Join("..", "..", "playground", "vuln-test", "pnpm-lock.yaml")
	lf, err := ParseLockfile(path)
	if err != nil {
		t.Fatalf("ParseLockfile: %v", err)
	}
	if edges := lf.ImportersOf("nonexistent-pkg", "1.0.0"); len(edges) != 0 {
		t.Errorf("expected no edges for nonexistent package, got %d", len(edges))
	}
	// Right name, wrong version.
	if edges := lf.ImportersOf("request", "999.0.0"); len(edges) != 0 {
		t.Errorf("expected no edges for wrong-version request, got %d", len(edges))
	}
}
