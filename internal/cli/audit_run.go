package cli

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/depx/internal/apperr"
	"github.com/projectdiscovery/depx/internal/audit"
	"github.com/projectdiscovery/depx/internal/github"
	"github.com/projectdiscovery/depx/internal/output"
	"github.com/projectdiscovery/depx/internal/registry"
	"github.com/spf13/cobra"
)

var (
	flagRequireClean  bool
	flagSBOMExport    string
	flagSBOMFormat    string
	flagOutput        string
	flagOutputFormats string
	flagSARIFExport   string
	flagExcludePkg    string
)

// addExcludePkgFlag registers the --exclude-pkg flag shared by audit and
// github. The file holds newline-separated "ecosystem:package" entries whose
// matches are dropped from findings (for suppressing known false positives).
func addExcludePkgFlag(cmd *cobra.Command) {
	cmd.Flags().StringVar(&flagExcludePkg, "exclude-pkg", "", "File of ecosystem:package entries to exclude from findings (newline-separated; '*' matches any ecosystem)")
}

// loadExcludeSet parses the --exclude-pkg file, if provided.
func loadExcludeSet() (audit.ExcludeSet, error) {
	path := strings.TrimSpace(flagExcludePkg)
	if path == "" {
		return audit.ExcludeSet{}, nil
	}
	return audit.LoadExcludeFile(path)
}

// addAuditOutputFlags registers the result-output flags shared by the audit and
// github commands. --output-format controls file exports (json, csv, txt);
// --output sets the base path; --sarif-export additionally writes a SARIF report.
func addAuditOutputFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&flagOutput, "output", "o", "", "Write export file(s) to this path or basename (default: temp files in text mode)")
	cmd.Flags().StringVar(&flagOutputFormats, "output-format", "", "Comma-separated export formats: json, csv, txt (default: json)")
	cmd.Flags().StringVar(&flagSARIFExport, "sarif-export", "", "Write a SARIF 2.1.0 report of findings to this path")
}

func githubClient() *github.Client {
	return github.NewClient(userAgent(), github.TokenFromEnv(), appCfg.Timeout)
}

func buildAuditOptions(ghClient *github.Client) (audit.Options, func()) {
	opts := audit.Options{}
	if ghClient != nil {
		opts.GitHub = &audit.GitHubOptions{
			Client:   ghClient,
			CacheDir: appCfg.CacheDir,
		}
	}
	stopProgress := func() {}
	if !flagJSON {
		prog, stop := output.NewAuditProgress(outOpts(), flagVerbose)
		opts.Progress = prog
		stopProgress = stop
	}
	opts.SBOMExport = flagSBOMExport
	opts.SBOMFormat = flagSBOMFormat
	opts.SBOMToolVersion = Version
	return opts, stopProgress
}

func runAudit(cmd *cobra.Command, paths []string, ghClient *github.Client, displayPaths ...[]string) error {
	excludeSet, err := loadExcludeSet()
	if err != nil {
		return apperr.Usage(err.Error())
	}
	svc := audit.NewService(intelProvider, registry.NewClient(userAgent(), appCfg.Timeout), appCfg.CacheDir)
	opts, stopProgress := buildAuditOptions(ghClient)
	opts.Exclude = excludeSet
	if len(displayPaths) > 0 && len(displayPaths[0]) > 0 {
		opts.DisplayPaths = displayPaths[0]
	}
	result, err := svc.AuditWithOptions(cmd.Context(), paths, opts)
	stopProgress()
	if err != nil {
		return err
	}
	if err := output.RenderAudit(outOpts(), Version, result); err != nil {
		return err
	}
	if err := emitAuditOutputs(result); err != nil {
		return err
	}
	return auditExitPolicy(result)
}

// emitAuditOutputs writes export files for each requested --output-format and,
// when requested, a SARIF report. Path notices print to stdout in text mode and
// to stderr in --json mode so stdout stays valid JSON.
func emitAuditOutputs(result *audit.Result) error {
	formats, err := output.ParseExportFormats(flagOutputFormats)
	if err != nil {
		return apperr.Usage(err.Error())
	}

	o := outOpts()
	noticeOut := o.Writer
	if flagJSON {
		noticeOut = o.ErrOut
	}
	c := o.Color()

	outputPath := strings.TrimSpace(flagOutput)
	writeExports := outputPath != "" || !flagJSON
	if writeExports {
		for _, format := range formats {
			path, err := output.ResolveExportPath(outputPath, format, formats)
			if err != nil {
				return apperr.Upstream("create export file", err)
			}
			written, err := output.WriteAuditExport(path, format, Version, "audit", result)
			if err != nil {
				return apperr.Upstream("write "+string(format)+" export", err)
			}
			printOutputNotice(noticeOut, c, format.ExportNoticeLabel(), written)
		}
	}

	if sarifPath := strings.TrimSpace(flagSARIFExport); sarifPath != "" {
		written, err := output.WriteSARIF(sarifPath, Version, result)
		if err != nil {
			return apperr.Upstream("write sarif report", err)
		}
		printOutputNotice(noticeOut, c, "SARIF report", written)
	}
	return nil
}

func printOutputNotice(w io.Writer, c aurora.Aurora, label, path string) {
	fmt.Fprintf(w, "  %s %s %s\n", c.Cyan("↳"), c.BrightBlack(label+":"), c.BrightBlue(absPath(path)))
}

// absPath returns the absolute form of p for display, falling back to the
// original value if resolution fails.
func absPath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
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
	addExcludePkgFlag(cmd)
	addAuditOutputFlags(cmd)
	return cmd
}
