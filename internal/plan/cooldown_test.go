package plan

import (
	"strings"
	"testing"
)

func TestCanBypassCooldown(t *testing.T) {
	tests := []struct {
		name           string
		edges          []DeclaredEdge
		patched        string
		wantOK         bool
		wantReasonSub  string // substring expected in the reason when !ok
	}{
		{
			name: "all ranges permit patched",
			edges: []DeclaredEdge{
				{Source: "y@2.0.0", DeclaredRange: "^1.0.0"},
				{Source: "z@3.0.0", DeclaredRange: ">=1.2.0"},
			},
			patched: "1.2.4",
			wantOK:  true,
		},
		{
			name: "exact pin blocks",
			edges: []DeclaredEdge{
				{Source: "y@2.0.0", DeclaredRange: "^1.0.0"},
				{Source: "z@3.0.0", DeclaredRange: "1.2.3"},
			},
			patched:       "1.2.4",
			wantOK:        false,
			wantReasonSub: "z@3.0.0",
		},
		{
			name: "tilde range blocks (newer minor)",
			edges: []DeclaredEdge{
				{Source: "y@2.0.0", DeclaredRange: "~1.2.0"},
			},
			patched:       "1.3.0",
			wantOK:        false,
			wantReasonSub: "does not permit",
		},
		{
			name: "tilde range permits same minor",
			edges: []DeclaredEdge{
				{Source: "y@2.0.0", DeclaredRange: "~1.2.0"},
			},
			patched: "1.2.5",
			wantOK:  true,
		},
		{
			name: "caret range permits same major",
			edges: []DeclaredEdge{
				{Source: "y@2.0.0", DeclaredRange: "^1.0.0"},
			},
			patched: "1.99.0",
			wantOK:  true,
		},
		{
			name: "caret range blocks major bump",
			edges: []DeclaredEdge{
				{Source: "y@2.0.0", DeclaredRange: "^1.0.0"},
			},
			patched:       "2.0.0",
			wantOK:        false,
			wantReasonSub: "y@2.0.0",
		},
		{
			name: "workspace: specifier ignored",
			edges: []DeclaredEdge{
				{Source: "apps/admin", DeclaredRange: "workspace:*"},
				{Source: "y@2.0.0", DeclaredRange: "^1.0.0"},
			},
			patched: "1.2.4",
			wantOK:  true,
		},
		{
			name:          "no edges",
			edges:         nil,
			patched:       "1.2.4",
			wantOK:        false,
			wantReasonSub: "no importers",
		},
		{
			name: "empty declared range",
			edges: []DeclaredEdge{
				{Source: "y@2.0.0", DeclaredRange: ""},
			},
			patched:       "1.2.4",
			wantOK:        false,
			wantReasonSub: "empty",
		},
		{
			name: "unparseable range",
			edges: []DeclaredEdge{
				{Source: "y@2.0.0", DeclaredRange: "not-a-range"},
			},
			patched:       "1.2.4",
			wantOK:        false,
			wantReasonSub: "cannot parse range",
		},
		{
			name: "unparseable patched version",
			edges: []DeclaredEdge{
				{Source: "y@2.0.0", DeclaredRange: "^1.0.0"},
			},
			patched:       "not-a-version",
			wantOK:        false,
			wantReasonSub: "invalid patched version",
		},
		{
			name: "first failing edge wins (deterministic-ish)",
			edges: []DeclaredEdge{
				{Source: "y@2.0.0", DeclaredRange: "1.2.3"},
				{Source: "z@3.0.0", DeclaredRange: "1.2.3"},
			},
			patched:       "1.2.4",
			wantOK:        false,
			wantReasonSub: "1.2.3",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, reason := CanBypassCooldown(tt.edges, tt.patched)
			if ok != tt.wantOK {
				t.Fatalf("CanBypassCooldown() ok = %v, want %v (reason=%q)", ok, tt.wantOK, reason)
			}
			if !ok && !strings.Contains(reason, tt.wantReasonSub) {
				t.Errorf("reason %q does not contain %q", reason, tt.wantReasonSub)
			}
		})
	}
}
