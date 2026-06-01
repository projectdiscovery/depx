package cli

import (
	"fmt"

	"github.com/projectdiscovery/depx/internal/apperr"
	"github.com/projectdiscovery/depx/internal/github"
	"github.com/projectdiscovery/depx/internal/output"
	"github.com/projectdiscovery/depx/internal/registry"
	"github.com/projectdiscovery/depx/internal/audit"
	"github.com/spf13/cobra"
)

var (
	flagRequireClean bool
	flagSBOMExport   string
	flagSBOMFormat   string
)

func githubClient() *github.Client {
	return github.NewClient(userAgent(), github.TokenFromEnv(), appCfg.Timeout)
}

func buildAuditOptions(ghClient *github.Client) audit.Options {
	opts := audit.Options{}
	if ghClient != nil {
		opts.GitHub = &audit.GitHubOptions{
			Client:   ghClient,
			CacheDir: appCfg.CacheDir,
		}
	}
	if !flagJSON {
		opts.Progress = output.NewAuditProgress(outOpts(), flagVerbose)
	}
	opts.SBOMExport = flagSBOMExport
	opts.SBOMFormat = flagSBOMFormat
	opts.SBOMToolVersion = Version
	return opts
}

func runAudit(cmd *cobra.Command, paths []string, ghClient *github.Client, displayPaths ...[]string) error {
	svc := audit.NewService(intelProvider, registry.NewClient(userAgent(), appCfg.Timeout))
	opts := buildAuditOptions(ghClient)
	if len(displayPaths) > 0 && len(displayPaths[0]) > 0 {
		opts.DisplayPaths = displayPaths[0]
	}
	result, err := svc.AuditWithOptions(cmd.Context(), paths, opts)
	if err != nil {
		return err
	}
	if err := output.RenderAudit(outOpts(), Version, result); err != nil {
		return err
	}
	return auditExitPolicy(result)
}

func auditExitPolicy(result *audit.Result) error {
	if !flagRequireClean {
		return nil
	}
	if result.Summary.Malicious > 0 {
		return apperr.Findings(fmt.Sprintf("found %d malicious package(s)", result.Summary.Malicious))
	}
	return nil
}

func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit [path...]",
		Short: "Audit dependencies for malicious packages (default: $HOME)",
		Long:  "Fast local audit against the OSV MAL database. With no paths, audits $HOME for lockfiles and global installs. Pass a lockfile or SBOM file path. For GitHub repositories use: depx github <target>",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runAudit(cmd, args, nil); err != nil {
				if apperr.ExitCode(err) == apperr.CodeFindings {
					return err
				}
				return apperr.Upstream("audit failed", err)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&flagRequireClean, "require-clean", false, "Exit 1 unless the audit is clean (no malicious packages)")
	cmd.Flags().StringVar(&flagSBOMExport, "sbom-export", "", "Write an SBOM of the audited dependencies to this file path")
	cmd.Flags().StringVar(&flagSBOMFormat, "sbom-format", "", "SBOM format: cyclonedx (default) or spdx")
	return cmd
}
