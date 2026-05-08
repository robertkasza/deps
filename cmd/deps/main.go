package main

import (
	"fmt"
	"os"

	"github.com/robertkasza/deps/internal/cli"
)

func main() {
	if err := cli.Run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "deps:", err)
		os.Exit(1)
	}
}
