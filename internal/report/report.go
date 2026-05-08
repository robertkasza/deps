// Package report formats a Plan as JSON, human-readable text, or markdown.
package report

import (
	"io"

	"github.com/robertkasza/deps/internal/pkgmgr"
)

// Format is the output format selector accepted on the CLI.
type Format string

const (
	FormatHuman    Format = "human"
	FormatJSON     Format = "json"
	FormatMarkdown Format = "markdown"
)

// Write renders a Plan to w in the chosen format.
//
// TODO: implement. JSON output is the CI contract — keep its shape stable.
func Write(p pkgmgr.Plan, format Format, w io.Writer) error {
	return nil
}
