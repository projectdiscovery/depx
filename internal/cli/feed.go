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

func runFeed(cmd *cobra.Command, _ []string) error {
	since, err := parseSince(flagSince)
	if err != nil {
		return apperr.Usage(err.Error())
	}
	limit, err := config.NormalizeFeedLimit(flagLimit, appCfg.Feed.Limit)
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
	return output.RenderFeed(outOpts(), Version, result)
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
