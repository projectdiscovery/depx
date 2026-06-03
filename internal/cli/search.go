package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/projectdiscovery/depx/internal/apperr"
	"github.com/projectdiscovery/depx/internal/config"
	"github.com/projectdiscovery/depx/internal/osv"
	"github.com/projectdiscovery/depx/internal/output"
	"github.com/projectdiscovery/depx/internal/search"
	"github.com/spf13/cobra"
)

var (
	flagSearchLimit int
	flagSearchList  bool
)

func newSearchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "search <query>",
		Short: "Search known malicious packages by name",
		Long:  "Search the malicious-package corpus for package names matching the query (substring match).",
		Args:  cobra.ExactArgs(1),
		RunE:  runSearch,
	}
	cmd.Flags().IntVarP(&flagSearchLimit, "limit", "n", 0, fmt.Sprintf("Max results shown (default %d)", config.DefaultLimit))
	cmd.Flags().BoolVar(&flagSearchList, "list", false, "One line per result (advisory header only)")
	return cmd
}

func runSearch(cmd *cobra.Command, args []string) error {
	limit, err := config.NormalizeFeedLimit(flagSearchLimit, appCfg.Feed.Limit)
	if err != nil {
		return apperr.Usage(err.Error())
	}

	initialMsg := "Searching malicious package corpus…"
	firstRun := false
	if intelProvider != nil {
		st := intelProvider.SyncStatus()
		firstRun = st.LastSuccess.IsZero()
		if firstRun {
			initialMsg = osv.WithFirstRunCacheNote("Downloading malicious package corpus from OSV…")
		}
	}

	sp := output.NewSpinner(outOpts(), initialMsg)
	sp.Start()
	svc := search.NewService(appCfg, intelProvider)
	result, err := svc.Run(cmd.Context(), search.Options{
		Query:     args[0],
		Ecosystem: flagEcosystem,
		Limit:     limit,
		OnStatus: func(msg string) {
			if msg == "" || !firstRun {
				return
			}
			// Index download progress is driven by OnProgress (includes %).
			if strings.HasPrefix(msg, "Downloading malicious package index…") {
				return
			}
			if strings.HasPrefix(msg, "Malicious package index ready") {
				return
			}
			if strings.HasPrefix(msg, "Downloading malicious package corpus from OSV") &&
				!strings.Contains(msg, osv.FirstRunCacheNote) {
				msg = osv.WithFirstRunCacheNote(msg)
			}
			sp.SetMessage(msg)
		},
		OnProgress: func(loaded, total int) {
			if !firstRun {
				return
			}
			msg := osv.FormatIndexDownloadProgress(loaded, total)
			msg = osv.WithFirstRunCacheNote(msg)
			sp.SetMessage(msg)
		},
	})
	sp.Stop()
	if err != nil {
		if os.Getenv("DEPX_OSV_URL") != "" || os.Getenv("DEPX_MODIFIED_INDEX_URL") != "" {
			depxLog("DEPX_OSV_URL or DEPX_MODIFIED_INDEX_URL is set — unset these outside e2e tests")
			depxLog("Run: unset DEPX_OSV_URL DEPX_MODIFIED_INDEX_URL")
		}
		return err
	}
	o := outOpts()
	o.List = flagSearchList
	if err := output.RenderSearch(o, Version, result); err != nil {
		return err
	}
	if result.Total == 0 && !flagJSON {
		maybeWarnSearchIndexIncomplete()
	}
	return nil
}

func maybeWarnSearchIndexIncomplete() {
	if os.Getenv("DEPX_OSV_URL") != "" || os.Getenv("DEPX_MODIFIED_INDEX_URL") != "" {
		depxLog("DEPX_OSV_URL or DEPX_MODIFIED_INDEX_URL is set — index sync is disabled outside e2e tests")
		depxLog("Run: unset DEPX_OSV_URL DEPX_MODIFIED_INDEX_URL")
		return
	}
	if intelProvider == nil {
		return
	}
	st := intelProvider.SyncStatus()
	if st.LastSuccess.IsZero() {
		depxLog("malicious-package index sync has not completed yet (indexed %d packages)", st.Packages)
		depxLog("First search downloads the OSV corpus once and caches it locally")
		if st.LastError != "" {
			depxLog("last sync error: %s", st.LastError)
		}
	}
}
