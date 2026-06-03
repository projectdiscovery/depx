package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/projectdiscovery/depx/internal/apperr"
	"github.com/projectdiscovery/depx/internal/config"
	"github.com/projectdiscovery/depx/internal/feed"
	"github.com/projectdiscovery/depx/internal/output"
	"github.com/spf13/cobra"
)

func newFeedCmd() *cobra.Command {
	var feedSince string
	var feedLimit int
	var feedList bool
	cmd := &cobra.Command{
		Use:   "feed",
		Short: "Show malicious-package feed cards",
		Long:  "List recent malicious package advisories as cards (no summary dashboard).",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFeed(cmd, feedSince, feedLimit, false, feedList)
		},
	}
	// Local flag vars: binding to the shared globals would clobber the root
	// command's --since default (pflag writes defaults at registration time).
	cmd.Flags().StringVar(&feedSince, "since", "3d", "Include advisories published within this window")
	cmd.Flags().IntVarP(&feedLimit, "limit", "n", 0, fmt.Sprintf("Result limit (max %d)", config.MaxFeedLimit))
	cmd.Flags().BoolVar(&feedList, "list", false, "One line per result (advisory header only)")
	return cmd
}

func runDefaultFeed(cmd *cobra.Command) error {
	return runFeed(cmd, flagSince, flagLimit, true, false)
}

func runFeed(cmd *cobra.Command, sinceRaw string, limitFlag int, withDashboard, list bool) error {
	since, err := parseSince(sinceRaw)
	if err != nil {
		return apperr.Usage(err.Error())
	}
	limit, err := config.NormalizeFeedLimit(limitFlag, appCfg.Feed.Limit)
	if err != nil {
		return apperr.Usage(err.Error())
	}
	svc := feed.NewService(appCfg, intelProvider)
	result, err := svc.List(cmd.Context(), feed.Options{
		Since:     since,
		Ecosystem: flagEcosystem,
		Limit:     limit,
	})
	if err != nil {
		return err
	}
	if withDashboard {
		return output.RenderFeedWithDashboard(outOpts(), Version, result)
	}
	o := outOpts()
	o.List = list
	return output.RenderFeed(o, Version, result)
}

func parseSince(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return config.DefaultSince, nil
	}
	if d, err := time.ParseDuration(raw); err == nil {
		return d, nil
	}
	if strings.HasSuffix(raw, "d") {
		var days int
		if _, err := fmt.Sscanf(raw, "%dd", &days); err == nil {
			return time.Duration(days) * 24 * time.Hour, nil
		}
	}
	if strings.HasSuffix(raw, "h") {
		var hours int
		if _, err := fmt.Sscanf(raw, "%dh", &hours); err == nil {
			return time.Duration(hours) * time.Hour, nil
		}
	}
	return 0, fmt.Errorf("invalid --since value %q", raw)
}
