package output

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/logrusorgru/aurora"

	"github.com/projectdiscovery/depx/internal/audit"
	"github.com/projectdiscovery/depx/internal/github"
)

func writeAuditResults(o Options, result *audit.Result) {
	c := o.color()
	fmt.Fprintln(o.Writer)
	fmt.Fprintln(o.Writer, c.Bold("Audit results"))
	writeCardSeparator(o.Writer, c)

	writeAuditSummaryRow(o, c, "Verdict", auditVerdictLabel(c, result.Summary))
	if target := auditTargetLabel(result); target != "" {
		writeAuditSummaryRow(o, c, "Target", target)
	}
	writeAuditSummaryRow(o, c, "Files", fmt.Sprintf("%d", result.Summary.Lockfiles))
	writeAuditSummaryRow(o, c, "Dependencies", fmt.Sprintf("%d", result.Summary.Total))
	if result.DurationMS > 0 {
		writeAuditSummaryRow(o, c, "Duration", formatAuditDuration(result.DurationMS))
	}
	if result.SBOMPath != "" {
		writeAuditSummaryRow(o, c, "SBOM", c.BrightBlue(result.SBOMPath).String())
	}

	fmt.Fprintln(o.Writer)

	if result.Summary.Total == 0 && result.Summary.Lockfiles == 0 {
		fmt.Fprintf(o.Writer, "  %s %s\n\n", c.Cyan("↳"), c.BrightWhite("Nothing to audit — no lockfiles, SBOMs, or dependencies found."))
		return
	}

	if result.Summary.Malicious == 0 {
		fmt.Fprintf(o.Writer, "  %s %s\n", c.Cyan("↳"), c.Green("No known malicious packages in audited dependencies."))
		if result.Summary.SkippedPlaceholders > 0 {
			fmt.Fprintf(o.Writer, "  %s %s\n", c.Cyan("↳"), c.BrightBlack(auditSkippedPlaceholdersHint(result.Summary.SkippedPlaceholders)))
		}
		fmt.Fprintf(o.Writer, "  %s %s\n\n", c.Cyan("↳"), c.BrightBlack(auditCheckedHint(result.Summary)))
		return
	}

	if !result.FindingsStreamed {
		for i, f := range result.Findings {
			if i > 0 {
				writeCardSeparator(o.Writer, c)
			}
			writeAuditFindingCard(o, f)
		}
	}

	writeAuditFindingsFooter(o.Writer, c, result)
}

func writeAuditSummaryRow(o Options, c aurora.Aurora, label, value string) {
	fmt.Fprintf(o.Writer, "  %-14s %s\n", c.BrightBlack(label+":"), value)
}

func auditVerdictLabel(c aurora.Aurora, summary audit.Summary) string {
	switch {
	case summary.Malicious > 0:
		return c.Red(fmt.Sprintf("MALICIOUS (%d)", summary.Malicious)).String()
	case summary.Suspicious > 0:
		return c.Yellow(fmt.Sprintf("SUSPICIOUS (%d)", summary.Suspicious)).String()
	default:
		return c.Green("CLEAN").String()
	}
}

func auditTargetLabel(result *audit.Result) string {
	if len(result.Paths) == 0 {
		return ""
	}
	paths := make([]string, 0, len(result.Paths))
	for _, p := range result.Paths {
		paths = append(paths, github.DisplayTarget(p))
	}
	if len(paths) == 1 {
		return paths[0]
	}
	if githubOwnersOnly(paths) {
		return formatTruncatedTargetList(paths, 8, "owners")
	}
	return formatTruncatedTargetList(paths, 2, "more")
}

func githubOwnersOnly(paths []string) bool {
	for _, p := range paths {
		owner := strings.TrimPrefix(p, "github.com/")
		if owner == "" || strings.Contains(owner, "/") {
			return false
		}
	}
	return true
}

func formatTruncatedTargetList(paths []string, show int, moreLabel string) string {
	if len(paths) <= show {
		return strings.Join(paths, ", ")
	}
	parts := paths[:show]
	extra := len(paths) - show
	if moreLabel == "owners" {
		return strings.Join(parts, ", ") + fmt.Sprintf(" +%d more owners", extra)
	}
	return strings.Join(parts, ", ") + fmt.Sprintf(" +%d more", extra)
}

func formatAuditDuration(ms int64) string {
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}
	d := time.Duration(ms) * time.Millisecond
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	m := int(d.Minutes())
	s := int(d.Seconds()) % 60
	if s == 0 {
		return fmt.Sprintf("%dm", m)
	}
	return fmt.Sprintf("%dm %ds", m, s)
}

func auditCheckedHint(summary audit.Summary) string {
	if summary.Lockfiles == 1 {
		return fmt.Sprintf("%d dependencies checked from 1 file", summary.Total)
	}
	return fmt.Sprintf("%d dependencies checked from %d files", summary.Total, summary.Lockfiles)
}

func auditSkippedPlaceholdersHint(n int) string {
	if n == 1 {
		return "1 registry placeholder dependency excluded (npm security stub)"
	}
	return fmt.Sprintf("%d registry placeholder dependencies excluded (npm security stubs)", n)
}

func writeAuditFindingsFooter(w io.Writer, c aurora.Aurora, result *audit.Result) {
	shown := len(result.Findings)
	if result.FindingsStreamed {
		shown = result.Summary.Malicious
	}
	msg := fmt.Sprintf("↳ %d malicious finding", shown)
	if shown != 1 {
		msg += "s"
	}
	msg += " · " + auditCheckedHint(result.Summary)
	if result.Summary.SkippedPlaceholders > 0 {
		msg += " · " + auditSkippedPlaceholdersHint(result.Summary.SkippedPlaceholders)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, c.BrightBlue(msg))
	fmt.Fprintln(w)
}
