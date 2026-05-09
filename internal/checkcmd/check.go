package checkcmd

import (
	"flag"
	"fmt"
	"io"

	"github.com/robertkasza/deps/internal/pnpm"
)

type Options struct {
	Dir      string
	Severity string
	Format   string
}

func Run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)

	opts := Options{}
	fs.StringVar(&opts.Dir, "dir", ".", "monorepo root (directory containing pnpm-workspace.yaml)")
	fs.StringVar(&opts.Severity, "severity", "moderate", "minimum severity to report (low|moderate|high|critical)")
	fs.StringVar(&opts.Format, "format", "human", "output format (human|json|markdown)")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}

	pm := pnpm.New()
	workspaces, err := pm.DiscoverWorkspaces(opts.Dir)
	if err != nil {
		return fmt.Errorf("discover workspaces: %w", err)
	}

	rootDir := opts.Dir
	for _, ws := range workspaces {
		if ws.IsRoot {
			rootDir = ws.Dir
			break
		}
	}
	fmt.Fprintf(stderr, "discovered %d workspace(s) under %s:\n", len(workspaces), rootDir)
	for _, ws := range workspaces {
		root := ""
		if ws.IsRoot {
			root = " (root)"
		}
		name := ws.Name
		if name == "" {
			name = "<unnamed>"
		}
		fmt.Fprintf(stdout, "  - %s%s  %s\n", name, root, ws.Dir)
	}
	return nil
}
