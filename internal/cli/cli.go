package cli

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/robertkasza/deps/internal/checkcmd"
	"github.com/robertkasza/deps/internal/fixcmd"
)

const usage = `deps — pnpm vulnerability remediation

Usage:
  deps <command> [flags]

Commands:
  check   Scan workspaces, classify advisories, emit a remediation plan (read-only)
  fix     Run check, then apply the plan (mutates package.json + lockfile)

Run "deps <command> -h" for command-specific flags.
`

func Run(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("no command given")
	}

	cmd, rest := args[0], args[1:]
	switch cmd {
	case "check":
		return checkcmd.Run(rest, os.Stdout, os.Stderr)
	case "fix":
		return fixcmd.Run(rest, os.Stdout, os.Stderr)
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, usage)
		return nil
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", cmd)
	}
}

// helper for subcommands to define a flagset that prints to stderr.
func NewFlagSet(name string, out io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(out)
	return fs
}
