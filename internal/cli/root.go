package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/projectdiscovery/depx/internal/apperr"
	"github.com/projectdiscovery/depx/internal/config"
	"github.com/projectdiscovery/depx/internal/intel"
	"github.com/projectdiscovery/depx/internal/output"
	"github.com/projectdiscovery/depx/internal/ref"
	"github.com/spf13/cobra"
)

var (
	Version = "v0.1.1"

	cfgPath           string
	flagJSON          bool
	flagVerbose       bool
	flagNoColor       bool
	flagSilent        bool
	flagEcosystem     string
	flagDisableUpdate bool
	flagUpdate        bool
	flagVersion       bool
	flagSince         string
	flagLimit         int
	flagList          bool
	flagRaw           bool

	appCfg        *config.Config
	intelProvider intel.Provider
)

func Execute() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	root := NewRootCmd()
	root.SetArgs(normalizePDStyleArgs(os.Args[1:]))
	root.SetContext(ctx)
	err := root.ExecuteContext(ctx)
	// Let any in-flight hourly refresh finish so the updated index persists.
	// The command's output has already been rendered; this only waits on the
	// background download, bounded by the configured network timeout.
	if intelProvider != nil {
		intelProvider.WaitBackgroundSync()
	}
	return err
}

// JSONEnabled reports whether the user passed --json / -j.
func JSONEnabled() bool { return flagJSON }

func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "depx",
		Short: "Malicious package & supply-chain intelligence",
		Long:  "depx — malicious package & supply-chain intelligence.",
		Args:  cobra.ArbitraryArgs,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if flagUpdate {
				runUpdate()
				os.Exit(0)
			}
			if flagVersion {
				showVersion()
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
				if args[0] == "check" {
					if len(args) == 1 {
						return cmd.Help()
					}
					return runChecks(cmd, args[1:])
				}
				if isSubcommand(args[0]) {
					return cmd.Help()
				}
				return runChecks(cmd, args)
			}
			if stdinIsPipe() {
				return runChecks(cmd, nil)
			}
			return runDefaultFeed(cmd)
		},
	}

	root.PersistentFlags().BoolVarP(&flagJSON, "json", "j", false, "JSON output")
	root.PersistentFlags().BoolVarP(&flagVerbose, "verbose", "v", false, "Extra audit/github detail (skip reasons, version-check errors)")
	root.PersistentFlags().BoolVar(&flagNoColor, "no-color", false, "Disable colors")
	root.PersistentFlags().BoolVar(&flagSilent, "silent", false, "Suppress banner and version info")
	root.PersistentFlags().StringVarP(&flagEcosystem, "ecosystem", "e", "", "Restrict package lookup to one ecosystem (default: all for bare names)")
	root.PersistentFlags().StringVar(&cfgPath, "config", "", "Config file path")
	root.PersistentFlags().BoolVar(&flagDisableUpdate, "disable-update-check", false, "Disable update check")
	root.PersistentFlags().BoolVar(&flagUpdate, "update", false, "Update depx to latest version")
	root.PersistentFlags().BoolVarP(&flagVersion, "version", "V", false, "Show version and exit")

	root.Flags().StringVar(&flagSince, "since", "3d", "Include advisories published within this window")
	root.Flags().IntVarP(&flagLimit, "limit", "n", 0, fmt.Sprintf("Feed result limit on default command (max %d; use depx github -n for repo caps)", config.MaxFeedLimit))
	root.Flags().BoolVar(&flagList, "list", false, "One line per result (no dashboard)")

	root.AddCommand(newFeedCmd())
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
	explicitConfig := cfgPath != ""
	if path == "" {
		path = config.DefaultConfigPath()
	}
	// An explicitly provided --config that doesn't exist is a user error; a
	// missing default config path silently falls back to built-in defaults.
	if explicitConfig {
		if _, statErr := os.Stat(path); statErr != nil {
			return apperr.Usage(fmt.Sprintf("config file not found: %s", path))
		}
	}
	var err error
	appCfg, err = config.Load(path)
	if err != nil {
		return apperr.Usage(err.Error())
	}
	if flagEcosystem != "" {
		if !ref.IsKnownEcosystem(flagEcosystem) {
			return apperr.Usage(fmt.Sprintf("unknown ecosystem %q (valid: %s)", flagEcosystem, strings.Join(ref.CheckEcosystems, ", ")))
		}
		appCfg.DefaultEcosystem = flagEcosystem
	}
	intelProvider, err = intel.New(Version, appCfg)
	if err != nil {
		return apperr.Usage(err.Error())
	}
	// The hourly refresh is triggered when a command loads a usable-but-stale
	// cache (see sync.loadIndex); Execute waits for it to persist. We do not also
	// kick a background sync here, which would double-fetch the export.
	return nil
}

func outOpts() output.Options {
	return output.NewOptions(flagJSON, flagNoColor)
}

func isSubcommand(name string) bool {
	switch name {
	case "feed", "audit", "search", "github", "id", "version", "update", "help":
		return true
	default:
		return false
	}
}

func userAgent() string {
	return fmt.Sprintf("depx/%s (+https://github.com/projectdiscovery/depx)", Version)
}
