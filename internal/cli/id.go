package cli

import (
	"encoding/json"
	"fmt"

	"github.com/projectdiscovery/depx/internal/apperr"
	"github.com/projectdiscovery/depx/internal/malindex"
	"github.com/projectdiscovery/depx/internal/output"
	"github.com/spf13/cobra"
)

func runIDLookups(cmd *cobra.Command, ids []string) error {
	vulns, err := withSpinner("Looking up advisory…", func() ([]*malindex.Vulnerability, error) {
		out := make([]*malindex.Vulnerability, 0, len(ids))
		for _, id := range ids {
			vuln, err := intelProvider.GetVuln(cmd.Context(), id)
			if err != nil {
				return nil, apperr.Upstream("lookup failed", err)
			}
			out = append(out, vuln)
		}
		return out, nil
	})
	if err != nil {
		return err
	}
	if flagRaw && len(vulns) == 1 {
		return renderRawVuln(vulns[0])
	}
	return output.RenderIDs(outOpts(), Version, vulns)
}

func renderRawVuln(vuln *malindex.Vulnerability) error {
	if flagJSON {
		enc, _ := json.Marshal(vuln)
		_, err := fmt.Fprintln(outOpts().Writer, string(enc))
		return err
	}
	fmt.Println(vuln.Summary)
	return nil
}

func newIDCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "id <MAL|GHSA|...>",
		Short: "Lookup advisory by ID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runIDLookups(cmd, args)
		},
	}
	cmd.Flags().BoolVar(&flagRaw, "raw", false, "Raw OSV record only")
	return cmd
}
