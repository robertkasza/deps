package checkcmd

import (
	"flag"
	"fmt"
	"io"
)

type Options struct {
	Cwd      string
	Severity string
	Format   string
}

func Run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)

	opts := Options{}
	fs.StringVar(&opts.Cwd, "cwd", ".", "monorepo root (directory containing pnpm-workspace.yaml)")
	fs.StringVar(&opts.Severity, "severity", "moderate", "minimum severity to report (low|moderate|high|critical)")
	fs.StringVar(&opts.Format, "format", "human", "output format (human|json|markdown)")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}

	fmt.Fprintf(stderr, "deps check: not implemented yet (cwd=%s severity=%s format=%s)\n",
		opts.Cwd, opts.Severity, opts.Format)
	return nil
}
