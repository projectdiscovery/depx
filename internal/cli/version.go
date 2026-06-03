package cli

import (
	"fmt"
	"os"

	updateutils "github.com/projectdiscovery/utils/update"
	"github.com/spf13/cobra"
)

const banner = `
       __               
  ____╱ ╱__  ____  _  __
 ╱ __  ╱ _ ╲╱ __ ╲│ │╱_╱
╱ ╱_╱ ╱  __╱ ╱_╱ ╱>  <  
╲__,_╱╲___╱ .___╱_╱│_│  
         ╱_╱            `

func showBanner() {
	fmt.Fprintf(os.Stderr, "%s%s\n\n", banner, Version)
}

func newVersionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Show version and check for updates",
		Run: func(cmd *cobra.Command, args []string) {
			showVersion()
		},
	}
	return cmd
}

func newUpdateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update depx to the latest version",
		Run: func(cmd *cobra.Command, args []string) {
			runUpdate()
		},
	}
	return cmd
}

func depxLog(format string, args ...any) {
	if flagSilent {
		return
	}
	fmt.Fprintf(os.Stderr, "[depx] "+format+"\n", args...)
}

func showVersionInfo() {
	if flagVerbose && intelProvider != nil {
		st := intelProvider.SyncStatus()
		if st.Packages > 0 {
			line := fmt.Sprintf("index %s: %d packages", st.Source, st.Packages)
			if !st.LastSuccess.IsZero() {
				line = fmt.Sprintf("index %s: %d packages, synced %s", st.Source, st.Packages, st.LastSuccess.Format("2006-01-02 15:04 MST"))
			}
			depxLog("%s", line)
			if st.Pending > 0 {
				depxLog("index sync pending: %d entries", st.Pending)
			}
		}
	}
}

func showVersion() {
	fmt.Fprintf(os.Stderr, "[depx] Current version %s\n", Version)
	if flagDisableUpdate {
		return
	}
	latest, err := updateutils.GetToolVersionCallback("depx", Version)()
	if err != nil {
		if flagVerbose {
			depxLog("version check failed: %v", err)
		}
		return
	}
	desc := updateutils.GetVersionDescription(Version, latest)
	if desc != "" {
		fmt.Fprintf(os.Stderr, "[depx] Current version %s %s\n", Version, desc)
		if latest != Version {
			fmt.Fprintf(os.Stderr, "[depx] To update: depx update  or  depx --update\n")
		}
		return
	}
	fmt.Fprintf(os.Stderr, "[depx] Current version %s (latest)\n", Version)
}

func runUpdate() {
	if flagDisableUpdate {
		fmt.Fprintf(os.Stderr, "[depx] Update check is disabled\n")
		return
	}
	fmt.Fprintf(os.Stderr, "[depx] Checking for updates...\n")
	updateutils.GetUpdateToolCallback("depx", Version)()
}
