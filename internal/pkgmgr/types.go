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
	GHSA            string   // e.g., "GHSA-xxxx-xxxx-xxxx"
	Severity        Severity
	Package         string   // vulnerable package name
	VulnerableRange string   // semver range that's vulnerable, e.g., "<4.1.3"
	FixedRange      string   // semver range with a fix, e.g., ">=4.1.3"
	Path            []string // dependency chain, root-first (e.g., ["request", "tough-cookie"])
	Workspace       Workspace
	URL             string   // advisory URL
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
	Reason string
}

// Unresolved represents a finding deps refuses to auto-remediate in MVP
// (e.g., requires a major-version jump, or no fix is published).
type Unresolved struct {
	Finding Finding
	Reason  string // e.g., "major-jump-required", "no-fix-available"
}

// Plan is the output of the plan stage and the input to apply.
type Plan struct {
	Actionable []Edit
	Unresolved []Unresolved
}
