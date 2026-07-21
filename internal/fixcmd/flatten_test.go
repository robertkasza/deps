package fixcmd

import (
	"testing"

	"github.com/robertkasza/deps/internal/pkgmgr"
)

// With sharedWorkspaceLockfile=false, each workspace owns its lockfile,
// so `pnpm audit --fix update` must run in EVERY workspace that received
// a cooldown-bypass edit. A name-keyed minimal set cover would skip
// workspaces sharing a package name (e.g. both dashboard and reactnative
// bypass "ws"), leaving the skipped workspace's vulnerable resolution in
// place and the advisory alive after re-audit.
func TestFlatten_CooldownDirsCoversEveryWorkspace(t *testing.T) {
	ws := func(dir string) pkgmgr.Workspace {
		return pkgmgr.Workspace{Dir: dir, PackageJSON: dir + "/package.json"}
	}
	cooldown := func(dir, pkg string) pkgmgr.Edit {
		return pkgmgr.Edit{Kind: pkgmgr.EditExcludeFromCooldown, Package: pkg, To: "1.2.3", File: "/root/pnpm-workspace.yaml"}
	}

	results := []WorkspaceResult{
		{Workspace: ws("/repo/dashboard"), Plan: pkgmgr.Plan{Actionable: []pkgmgr.Edit{cooldown("/repo/dashboard", "ws")}}},
		{Workspace: ws("/repo/examples/quickstarts/reactnative"), Plan: pkgmgr.Plan{Actionable: []pkgmgr.Edit{cooldown("/repo/examples/quickstarts/reactnative", "ws")}}},
		{Workspace: ws("/repo/docs"), Plan: pkgmgr.Plan{Actionable: []pkgmgr.Edit{cooldown("/repo/docs", "tar")}}},
	}

	_, _, _, cooldownDirs, _ := flatten(results)

	want := map[string]bool{
		"/repo/dashboard":                        true,
		"/repo/examples/quickstarts/reactnative": true,
		"/repo/docs":                             true,
	}
	if len(cooldownDirs) != len(want) {
		t.Fatalf("cooldownDirs = %v, want all %d workspaces", cooldownDirs, len(want))
	}
	for _, d := range cooldownDirs {
		if !want[d] {
			t.Errorf("unexpected dir %q", d)
		}
		delete(want, d)
	}
	for d := range want {
		t.Errorf("workspace %q with a cooldown-bypass edit was dropped — its lockfile would never be re-resolved", d)
	}
}
