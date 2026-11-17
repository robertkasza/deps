package pkgmgr

// Workspace identifies a single package within a monorepo (or the
// synthetic single-workspace of a non-monorepo project).
type Workspace struct {
	// Dir is the absolute path to the workspace's root directory.
	Dir string
	// RelDir is the workspace's directory relative to the monorepo root
	// using forward slashes (e.g., "apps/admin"). Empty for the root
	// workspace itself.
	RelDir string
	// PackageJSON is the absolute path to the workspace's package.json.
	PackageJSON string
	// MonorepoRoot is the absolute path to the monorepo root directory
	// (the one containing pnpm-workspace.yaml). Same value on every
	// Workspace returned by a single DiscoverWorkspaces call. Equal to
	// Dir for the root workspace itself, and equal to Dir for a
	// single-package repo.
	MonorepoRoot string
	// Name is the value of the "name" field in package.json (may be empty
	// for unnamed packages).
	Name string
	// IsRoot is true for the monorepo root workspace (the one alongside
	// pnpm-workspace.yaml). The root is where pnpm.overrides live.
	IsRoot bool
}

// Severity matches npm advisory severity levels.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityModerate Severity = "moderate"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Advisory is a single vulnerability finding attributed to a workspace.
// It is the package-manager-agnostic shape that downstream stages consume.
type Advisory struct {
	GHSA            string // e.g., "GHSA-xxxx-xxxx-xxxx"
	Severity        Severity
	Package         string   // vulnerable package name
	VulnerableRange string   // semver range that's vulnerable, e.g., "<4.1.3"
	FixedRange      string   // semver range with a fix, e.g., ">=4.1.3"
	Path            []string // dependency chain, root-first (e.g., ["request", "tough-cookie"])
	Workspace       Workspace
	URL             string // advisory URL

	// AuditPath is the dependency path exactly as the package manager's
	// audit reported it (e.g., ".>request>tough-cookie"), including any
	// workspace segment. Used to match audit-ci path allowlist entries.
	AuditPath string
	// Version is the installed version of Package at this path, when the
	// audit reports it.
	Version string
}

// FindingKind distinguishes whether a vulnerable package is declared
// directly in the workspace or pulled in via another dep.
type FindingKind string

const (
	FindingDirect     FindingKind = "direct"
	FindingTransitive FindingKind = "transitive"
)

// Finding is an Advisory enriched with its relationship to the workspace.
// Produced by the triage package.
type Finding struct {
	Advisory Advisory
	Kind     FindingKind
	// Parent is the top-level dependency that pulls in the vulnerable
	// package, set only when Kind == FindingTransitive.
	Parent string
}

// EditKind enumerates the remediation actions deps emits.
type EditKind string

const (
	EditBumpDirect          EditKind = "bump-direct"
	EditBumpParent          EditKind = "bump-parent"
	EditOverrideAdd         EditKind = "override-add"
	EditOverrideConsolidate EditKind = "override-consolidate"
	// EditExcludeFromCooldown adds an exact-version entry to
	// pnpm-workspace.yaml's minimumReleaseAgeExclude list, lifting the
	// install cooldown for one specific patched version so normal
	// resolution can pick it up. Used when every importer's declared
	// range already permits the patched version and the only blocker
	// is the cooldown filter. Edit.Package + Edit.To carry the entry
	// (e.g., "turbo" + "2.9.14"); Edit.File is the pnpm-workspace.yaml
	// at the monorepo root.
	EditExcludeFromCooldown EditKind = "exclude-from-cooldown"
)

// Edit is a single file mutation a PkgManager will apply.
type Edit struct {
	Kind EditKind

	// File is the absolute path to the package.json being mutated.
	File string

	// Package is the package being bumped or overridden.
	Package string

	// For bump-direct / bump-parent: which package.json field
	// ("dependencies" or "devDependencies"). Empty for overrides.
	Field string

	// From is the existing version constraint (e.g., "^4.17.20"). Empty
	// for new override entries.
	From string

	// To is the new version constraint (e.g., "^4.17.21").
	To string

	// VulnerableRange is the override key suffix (e.g., "<4.1.3").
	// Set only for override edits.
	VulnerableRange string

	// Reason is a short human-readable explanation, used in reports.
	// For override edits this is concatenated across merges, so it
	// must stay short — one clause per source override edit.
	Reason string

	// RejectionNotes records why higher rungs of the remediation
	// ladder weren't chosen for this edit (e.g., "parent-bump not
	// viable: …; cooldown-bypass not viable: …"). Unlike Reason,
	// this is *not* concatenated when overrides merge — the first
	// non-empty value is kept, since the rejection story is similar
	// across same-vuln-pkg overrides from different parents.
	RejectionNotes string
}

// Unresolved represents a finding deps refuses to auto-remediate in MVP
// (e.g., requires a major-version jump, or no fix is published).
type Unresolved struct {
	Finding Finding
	Reason  string // e.g., "major-jump-required", "no-fix-available"
	// Detail optionally explains Reason for this finding in prose.
	Detail string
}

// Plan is the output of the plan stage and the input to apply.
type Plan struct {
	Actionable []Edit
	Unresolved []Unresolved
}

// ImporterEdge describes one place in a resolved dep tree where a
// target package@version appears as a direct dependency. Used by
// plan's cooldown-bypass remediation to walk back from a vulnerable
// package to every importer that declared it.
//
// For workspace-direct edges (IsWorkspace == true), DeclaredRange is
// filled from the lockfile's specifier field (the range that lives in
// the workspace's package.json). For transitive edges, DeclaredRange
// is empty — the caller must fetch it from the npm registry using
// ImporterName + ImporterVersion, since lockfiles don't preserve the
// declared ranges of transitive packages.
type ImporterEdge struct {
	IsWorkspace     bool
	ImporterName    string // workspace relative dir, or transitive package name
	ImporterVersion string // empty for workspaces; bare version for transitive
	DeclaredRange   string // filled for workspace edges only
}
