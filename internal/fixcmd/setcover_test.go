package fixcmd

import (
	"sort"
	"testing"
)

func TestGreedySetCover(t *testing.T) {
	tests := []struct {
		name      string
		input     map[string]map[string]bool
		wantSize  int
		wantElems []string // sorted; empty means "any pick is fine, only size matters"
	}{
		{
			name:     "empty",
			input:    nil,
			wantSize: 0,
		},
		{
			// Example from user:
			// dashboard{b,c}, docs{a,b,c}, react-apollo{d}
			// → docs covers a,b,c; react-apollo covers d. 2 runs.
			name: "two-workspace cover",
			input: map[string]map[string]bool{
				"dashboard":    {"b": true, "c": true},
				"docs":         {"a": true, "b": true, "c": true},
				"react-apollo": {"d": true},
			},
			wantSize:  2,
			wantElems: []string{"docs", "react-apollo"},
		},
		{
			// Example: docs{a,b,c,d} covers everything → 1 run.
			name: "single workspace covers all",
			input: map[string]map[string]bool{
				"dashboard":    {"b": true, "c": true},
				"docs":         {"a": true, "b": true, "c": true, "d": true},
				"react-apollo": {"d": true},
			},
			wantSize:  1,
			wantElems: []string{"docs"},
		},
		{
			// Example: dashboard{a}, docs{b}, react-apollo{c}.
			// No overlap → all three must run.
			name: "disjoint sets",
			input: map[string]map[string]bool{
				"dashboard":    {"a": true},
				"docs":         {"b": true},
				"react-apollo": {"c": true},
			},
			wantSize:  3,
			wantElems: []string{"dashboard", "docs", "react-apollo"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Copy input because greedySetCover mutates it.
			input := map[string]map[string]bool{}
			for ws, pkgs := range tt.input {
				input[ws] = map[string]bool{}
				for p := range pkgs {
					input[ws][p] = true
				}
			}
			got := greedySetCover(input)
			if len(got) != tt.wantSize {
				t.Fatalf("greedySetCover() size = %d, want %d (got=%v)", len(got), tt.wantSize, got)
			}
			if len(tt.wantElems) > 0 {
				sorted := append([]string(nil), got...)
				sort.Strings(sorted)
				if !equalSlices(sorted, tt.wantElems) {
					t.Errorf("greedySetCover() = %v, want %v", sorted, tt.wantElems)
				}
			}
		})
	}
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
