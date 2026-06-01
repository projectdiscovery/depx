package cli

import (
	"fmt"

	"github.com/projectdiscovery/depx/internal/apperr"
	"github.com/projectdiscovery/depx/internal/config"
	"github.com/projectdiscovery/depx/internal/output"
	"github.com/projectdiscovery/depx/internal/search"
	"github.com/spf13/cobra"
)

var flagSearchLimit int

func newSearchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "search <query>",
		Short: "Search known malicious packages by name",
		Long:  "Search the malicious-package corpus for package names matching the query (substring match).",
		Args:  cobra.ExactArgs(1),
		RunE:  runSearch,
	}
	cmd.Flags().IntVarP(&flagSearchLimit, "limit", "n", 0, fmt.Sprintf("Result limit (default %d)", config.DefaultLimit))
	return cmd
}

func runSearch(cmd *cobra.Command, args []string) error {
	limit, err := config.NormalizeFeedLimit(flagSearchLimit, appCfg.Feed.Limit)
	if err != nil {
		return apperr.Usage(err.Error())
	}

	svc := search.NewService(appCfg, intelProvider)
	result, err := svc.Run(cmd.Context(), search.Options{
		Query:     args[0],
		Ecosystem: flagEcosystem,
		Limit:     limit,
	})
	if err != nil {
		return err
	}
	return output.RenderSearch(outOpts(), Version, result)
}
