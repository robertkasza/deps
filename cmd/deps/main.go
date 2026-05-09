package main

import (
	"fmt"
	"os"

	"github.com/robertkasza/deps/internal/cli"
)

// codedError is satisfied by errors that carry a desired exit code
// (e.g., checkcmd.exitErr signaling 0/10/20).
type codedError interface {
	Code() int
}

func main() {
	err := cli.Run(os.Args[1:])
	if err == nil {
		return
	}
	if msg := err.Error(); msg != "" {
		fmt.Fprintln(os.Stderr, "deps:", msg)
	}
	if c, ok := err.(codedError); ok {
		os.Exit(c.Code())
	}
	os.Exit(1)
}
