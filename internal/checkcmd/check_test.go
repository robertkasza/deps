package checkcmd

import "testing"

// Exit-code contract for `deps check`:
//   0  clean
//   1  tool error (workspace failures)
//  10  actionable or unresolved findings present
//  20  reserved for `deps fix` (`unresolved-after-apply`); never returned here
func TestDecideExit(t *testing.T) {
	cases := []struct {
		name                  string
		actionable, unresolved, failed int
		wantNil               bool
		wantCode              int
	}{
		{"clean", 0, 0, 0, true, 0},
		{"actionable only", 3, 0, 0, false, 10},
		{"unresolved only", 0, 2, 0, false, 10},
		{"both present", 1, 1, 0, false, 10},
		{"failure trumps findings", 5, 5, 1, false, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := decideExit(tc.actionable, tc.unresolved, tc.failed)
			if tc.wantNil {
				if err != nil {
					t.Fatalf("want nil, got %v", err)
				}
				return
			}
			ee, ok := err.(exitErr)
			if !ok {
				t.Fatalf("want exitErr, got %T (%v)", err, err)
			}
			if ee.Code() != tc.wantCode {
				t.Fatalf("want code %d, got %d", tc.wantCode, ee.Code())
			}
			if tc.wantCode == 20 {
				t.Fatalf("check must never return code 20; that is reserved for fix")
			}
		})
	}
}
