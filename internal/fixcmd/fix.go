package fixcmd

import (
	"flag"
	"fmt"
	"io"
)

type Options struct {
	Dir      string
	Severity string
	DryRun   bool
}

func Run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("fix", flag.ContinueOnError)
	fs.SetOutput(stderr)

	opts := Options{}
	fs.StringVar(&opts.Dir, "dir", ".", "monorepo root (directory containing pnpm-workspace.yaml)")
	fs.StringVar(&opts.Severity, "severity", "moderate", "minimum severity to act on (low|moderate|high|critical)")
	fs.BoolVar(&opts.DryRun, "dry-run", false, "compute the plan but do not write changes")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}

	fmt.Fprintf(stderr, "deps fix: not implemented yet (dir=%s severity=%s dry-run=%v)\n",
		opts.Dir, opts.Severity, opts.DryRun)
	return nil
}
