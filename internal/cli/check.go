package cli

import (
	"context"
	"strings"

	"github.com/projectdiscovery/depx/internal/apperr"
	"github.com/projectdiscovery/depx/internal/check"
	"github.com/projectdiscovery/depx/internal/output"
	"github.com/projectdiscovery/depx/internal/ref"
	"github.com/projectdiscovery/depx/internal/registry"
	"github.com/spf13/cobra"
)

func runChecks(cmd *cobra.Command, args []string) error {
	refs, err := resolveCheckRefs(args)
	if err != nil {
		return err
	}

	var pkgRefs []string
	var advisoryIDs []string
	for _, input := range refs {
		if ref.IsAdvisoryID(input) {
			advisoryIDs = append(advisoryIDs, strings.TrimSpace(input))
			continue
		}
		pkgRefs = append(pkgRefs, input)
	}
	if len(advisoryIDs) > 0 && len(pkgRefs) > 0 {
		return apperr.Usage("cannot mix advisory IDs with package refs; use separate invocations")
	}
	if len(advisoryIDs) > 0 {
		return runIDLookups(cmd, advisoryIDs)
	}

	svc := check.NewService(intelProvider, registry.NewClient(userAgent(), appCfg.Timeout), appCfg.CacheDir)

	results := make([]check.Result, len(pkgRefs))

	if _, err := withSpinner("Checking packages…", func() (struct{}, error) {
		var bareItems []check.BareRef
		var bareIndexes []int

		for i, input := range pkgRefs {
			if flagEcosystem != "" || ref.HasExplicitEcosystem(input) {
				result, checkErr := checkRef(cmd.Context(), svc, input)
				if checkErr != nil {
					return struct{}{}, checkErr
				}
				results[i] = *result
				continue
			}
			name, version, parseErr := ref.ParseBare(input)
			if parseErr != nil {
				return struct{}{}, parseErr
			}
			bareItems = append(bareItems, check.BareRef{Name: name, Version: version})
			bareIndexes = append(bareIndexes, i)
		}

		if len(bareItems) > 0 {
			batch, batchErr := svc.CheckAllMany(cmd.Context(), bareItems)
			if batchErr != nil {
				return struct{}{}, apperr.Upstream("check failed", batchErr)
			}
			for j, idx := range bareIndexes {
				results[idx] = batch[j]
			}
		}
		return struct{}{}, nil
	}); err != nil {
		return err
	}

	return output.RenderChecks(outOpts(), Version, results)
}

func checkRef(ctx context.Context, svc *check.Service, input string) (*check.Result, error) {
	if flagEcosystem != "" || ref.HasExplicitEcosystem(input) {
		defaultEco := appCfg.DefaultEcosystem
		if defaultEco == "" {
			defaultEco = "npm"
		}
		pkgRef, parseErr := ref.Parse(input, defaultEco)
		if parseErr != nil {
			return nil, parseErr
		}
		result, err := svc.Check(ctx, pkgRef)
		if err != nil {
			return nil, apperr.Upstream("check failed", err)
		}
		return result, nil
	}
	name, version, parseErr := ref.ParseBare(input)
	if parseErr != nil {
		return nil, parseErr
	}
	result, err := svc.CheckAll(ctx, name, version)
	if err != nil {
		return nil, apperr.Upstream("check failed", err)
	}
	return result, nil
}
