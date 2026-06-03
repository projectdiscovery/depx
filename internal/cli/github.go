package cli

import (
	"fmt"

	"github.com/projectdiscovery/depx/internal/apperr"
	"github.com/projectdiscovery/depx/internal/config"
	gh "github.com/projectdiscovery/depx/internal/github"
	"github.com/spf13/cobra"
)

var flagGitHubLimit int

func newGitHubCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "github [target...]",
		Short: "Audit GitHub repositories via dependency-graph SBOM",
		Long: `Fetch SPDX SBOM exports from GitHub and audit dependencies for malicious packages.

With no targets and a token set, audits repositories your account can access
(owned, collaborated, and organization member repos), capped by --limit.

Targets may be:
  - https://github.com/owner/repo(.git)
  - https://github.com/owner (org or user — lists repositories)
  - owner/repo
  - owner (lists org or user repositories, capped by --limit)

Set DEPX_GITHUB_TOKEN, GITHUB_TOKEN, or GH_TOKEN for private repos, higher rate limits, and default target discovery.`,
		Args: cobra.ArbitraryArgs,
		RunE: runGitHub,
	}
	cmd.Flags().IntVarP(&flagGitHubLimit, "limit", "n", 0, fmt.Sprintf("Max repos when target is an org/user (default %d with a token, %d without; max %d)", config.DefaultGitHubRepoLimit, config.DefaultGitHubRepoLimitUnauth, config.MaxGitHubRepoLimit))
	cmd.Flags().BoolVar(&flagRequireClean, "require-clean", false, "Exit 1 unless the audit is clean (no malicious packages)")
	addExcludePkgFlag(cmd)
	addAuditOutputFlags(cmd)
	return cmd
}

func runGitHub(cmd *cobra.Command, args []string) error {
	authenticated := gh.TokenFromEnv() != ""
	limit, err := config.NormalizeGitHubRepoLimit(flagGitHubLimit, authenticated)
	if err != nil {
		return apperr.Usage(err.Error())
	}

	if len(args) == 0 && !authenticated {
		return apperr.Usage("provide a GitHub target, or set DEPX_GITHUB_TOKEN, GITHUB_TOKEN, or GH_TOKEN to scan accessible repositories")
	}

	if !authenticated && !flagJSON && !flagSilent {
		prefix := outOpts().Color().BrightBlack("[depx] ").String()
		fmt.Fprintf(cmd.ErrOrStderr(),
			"%sUnauthenticated GitHub (~60 req/hr); limiting to %d parallel repos. Set GITHUB_TOKEN to raise the limit.\n",
			prefix, limit,
		)
	}

	client := githubClient()
	repos, err := withSpinner("Resolving GitHub repositories…", func() ([]gh.Repo, error) {
		return client.ResolveRepos(cmd.Context(), args, limit)
	})
	if err != nil {
		return apperr.Usage(err.Error())
	}

	var displayPaths []string
	if len(args) == 0 {
		displayPaths = gh.DisplayOwners(repos)
	} else {
		displayPaths, err = gh.DisplayTargets(args)
		if err != nil {
			return apperr.Usage(err.Error())
		}
	}

	refs := make([]string, len(repos))
	for i, repo := range repos {
		refs[i] = repo.URL()
	}

	if err := runAudit(cmd, refs, client, displayPaths); err != nil {
		if apperr.ExitCode(err) == apperr.CodeFindings {
			return err
		}
		return apperr.Upstream("github audit failed", err)
	}
	return nil
}
