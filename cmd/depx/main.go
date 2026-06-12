package main

import (
	"fmt"
	"os"

	"github.com/projectdiscovery/depx/internal/apperr"
	"github.com/projectdiscovery/depx/internal/cli"
	"github.com/projectdiscovery/depx/internal/output"
)

func main() {
	if err := cli.Execute(); err != nil {
		code := apperr.ExitCode(err)
		if code == 0 {
			code = apperr.CodeUsage
		}
		if cli.JSONEnabled() {
			_ = output.WriteErrorJSON(os.Stdout, cli.Version, code, err.Error())
		} else {
			_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		os.Exit(code)
	}
}
