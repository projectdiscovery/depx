package output

import (
	"encoding/csv"
	"os"
	"strings"
	"time"

	"github.com/projectdiscovery/depx/internal/audit"
	"github.com/projectdiscovery/depx/internal/github"
)

var auditCSVHeader = []string{
	"verdict",
	"ecosystem",
	"name",
	"version",
	"ids",
	"summary",
	"campaign",
	"published_at",
	"modified_at",
	"source",
	"source_type",
	"lockfile",
	"project_dir",
	"project_url",
	"registry_url",
}

// WriteAuditCSV writes one row per finding to path. When there are no findings,
// a single summary row captures the audit verdict and scan stats.
func WriteAuditCSV(path string, result *audit.Result) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	w := csv.NewWriter(f)
	if err := w.Write(auditCSVHeader); err != nil {
		return err
	}
	if len(result.Findings) == 0 {
		if err := w.Write(auditCSVSummaryRow(result)); err != nil {
			return err
		}
	} else {
		for _, finding := range result.Findings {
			if err := w.Write(auditFindingCSVRow(finding)); err != nil {
				return err
			}
		}
	}
	w.Flush()
	return w.Error()
}

func auditCSVSummaryRow(result *audit.Result) []string {
	return []string{
		auditCSVVerdict(result.Summary),
		"",
		"",
		"",
		"",
		auditCSVSummaryText(result),
		"",
		"",
		"",
		"",
		"",
		"",
		auditCSVTarget(result),
		"",
		"",
	}
}

func auditCSVVerdict(summary audit.Summary) string {
	switch {
	case summary.Malicious > 0:
		return "malicious"
	case summary.Suspicious > 0:
		return "suspicious"
	default:
		return "clean"
	}
}

func auditCSVTarget(result *audit.Result) string {
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
	return strings.Join(paths, "; ")
}

func auditCSVSummaryText(result *audit.Result) string {
	if result.Summary.Total == 0 && result.Summary.Lockfiles == 0 {
		return "Nothing to audit — no lockfiles, SBOMs, or dependencies found."
	}
	parts := []string{"No known malicious packages in audited dependencies."}
	if result.Summary.SkippedPlaceholders > 0 {
		parts = append(parts, auditSkippedPlaceholdersHint(result.Summary.SkippedPlaceholders))
	}
	parts = append(parts, auditCheckedHint(result.Summary))
	if result.DurationMS > 0 {
		parts = append(parts, "duration="+formatAuditDuration(result.DurationMS))
	}
	return strings.Join(parts, " ")
}

func auditFindingCSVRow(f audit.Finding) []string {
	return []string{
		f.Verdict,
		f.Ecosystem,
		f.Name,
		f.Version,
		strings.Join(f.IDs, ";"),
		f.Summary,
		f.Campaign,
		formatCSVTime(f.Published),
		formatCSVTime(f.ModifiedAt),
		f.Source,
		f.SourceType,
		f.Lockfile,
		f.ProjectDir,
		f.ProjectURL,
		f.PackageURL,
	}
}

func formatCSVTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
