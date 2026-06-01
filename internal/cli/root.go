package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/projectdiscovery/depx/internal/apperr"
	"github.com/projectdiscovery/depx/internal/config"
	"github.com/projectdiscovery/depx/internal/intel"
	"github.com/projectdiscovery/depx/internal/output"
	"github.com/spf13/cobra"
)

var (
	Version = "v0.1.0"

	cfgPath           string
	flagJSON          bool
	flagVerbose       bool
	flagNoColor       bool
	flagSilent        bool
	flagEcosystem     string
	flagTimeout       time.Duration
	flagDisableUpdate bool
	flagUpdate        bool
	flagSince         string
	flagLimit         int
	flagRaw           bool

	appCfg    *config.Config
	intelProvider intel.Provider
)

func Execute() error {
	root := NewRootCmd()
	return root.Execute()
}

func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "depx",
		Short: "Dependency explorer and auditor — surface malicious packages and supply-chain risks",
		Long:  "depx — dependency explorer and auditor. Surface malicious packages and supply-chain risks. Default: recent compromised packages.",
		Args:  cobra.ArbitraryArgs,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if flagUpdate {
				runUpdate()
				os.Exit(0)
			}
			if !flagSilent {
				showBanner()
			}
			if err := initApp(cmd); err != nil {
				return err
			}
			if !flagSilent && !flagJSON && cmd.Name() != "version" && cmd.Name() != "update" {
				showVersionInfo()
			}
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				if isSubcommand(args[0]) {
					return cmd.Help()
				}
				return runChecks(cmd, args)
			}
			if stdinIsPipe() {
				return runChecks(cmd, nil)
			}
			return runFeed(cmd, args)
		},
	}

	root.PersistentFlags().BoolVarP(&flagJSON, "json", "j", false, "JSON output")
	root.PersistentFlags().BoolVarP(&flagVerbose, "verbose", "v", false, "Extra audit/github detail (skip reasons, version-check errors)")
	root.PersistentFlags().BoolVar(&flagNoColor, "no-color", false, "Disable colors")
	root.PersistentFlags().BoolVar(&flagSilent, "silent", false, "Suppress banner and version info")
	root.PersistentFlags().StringVarP(&flagEcosystem, "ecosystem", "e", "", "Restrict package lookup to one ecosystem (default: all for bare names)")
	root.PersistentFlags().DurationVar(&flagTimeout, "timeout", config.DefaultTimeout, "Request timeout")
	root.PersistentFlags().StringVar(&cfgPath, "config", "", "Config file path")
	root.PersistentFlags().BoolVar(&flagDisableUpdate, "disable-update-check", false, "Disable update check")
	root.PersistentFlags().BoolVar(&flagUpdate, "update", false, "Update depx to latest version")

	root.Flags().StringVar(&flagSince, "since", "24h", "Feed time window")
	root.Flags().IntVarP(&flagLimit, "limit", "n", 0, fmt.Sprintf("Feed result limit on default command (max %d; use depx github -n for repo caps)", config.MaxFeedLimit))

	root.AddCommand(newAuditCmd())
	root.AddCommand(newSearchCmd())
	root.AddCommand(newGitHubCmd())
	root.AddCommand(newIDCmd())
	root.AddCommand(newVersionCmd())
	root.AddCommand(newUpdateCmd())

	root.CompletionOptions.DisableDefaultCmd = true

	return root
}

func initApp(cmd *cobra.Command) error {
	path := cfgPath
	if path == "" {
		path = config.DefaultConfigPath()
	}
	var err error
	appCfg, err = config.Load(path)
	if err != nil {
		return apperr.Usage(err.Error())
	}
	if flagTimeout > 0 {
		appCfg.Timeout = flagTimeout
	}
	if flagEcosystem != "" {
		appCfg.DefaultEcosystem = flagEcosystem
	}
	intelProvider, err = intel.New(Version, appCfg)
	if err != nil {
		return apperr.Usage(err.Error())
	}
	if err := intel.SeedEmbeddedCache(appCfg.CacheDir); err != nil {
		return apperr.Upstream("embedded intel bundle", err)
	}
	intelProvider.StartBackgroundSync(context.Background())
	return nil
}

func outOpts() output.Options {
	return output.NewOptions(flagJSON, flagNoColor)
}

func isSubcommand(name string) bool {
	switch name {
	case "audit", "search", "github", "id", "version", "update", "help":
		return true
	default:
		return false
	}
}

func userAgent() string {
	return fmt.Sprintf("depx/%s (+https://github.com/projectdiscovery/depx)", Version)
}
