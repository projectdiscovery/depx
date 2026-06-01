package main

import (
	"fmt"
	"os"

	"github.com/projectdiscovery/depx/internal/apperr"
	"github.com/projectdiscovery/depx/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		code := apperr.ExitCode(err)
		if code == 0 {
			code = apperr.CodeUsage
		}
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(code)
	}
}
