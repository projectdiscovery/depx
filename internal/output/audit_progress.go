package output

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/logrusorgru/aurora"

	"github.com/projectdiscovery/depx/internal/audit"
)

func NewAuditProgress(o Options, verbose bool) *audit.Progress {
	errOut := o.ErrOut
	if errOut == nil {
		errOut = os.Stderr
	}
	cardOut := o.Writer
	if cardOut == nil {
		cardOut = os.Stdout
	}
	c := aurora.NewAurora(!o.NoColor && os.Getenv("NO_COLOR") == "")
	ui := &auditProgressUI{
		errOut:  errOut,
		c:       c,
		verbose: verbose,
	}
	cardOpts := Options{Writer: cardOut, NoColor: o.NoColor}

	return &audit.Progress{
		OnDiscover: func(found int, currentPath string) {
			ui.progress(fmt.Sprintf("Discovering lockfiles... %d found | %s",
				found, shortenPath(currentPath, 70)))
		},
		OnDiscovered: func(lockfileCount int, root string) {
			ui.clear()
			ui.line(fmt.Sprintf("Found %d lockfiles in %s", lockfileCount, shortenPath(root, 80)))
		},
		OnLockfile: func(index, total int, path string, depCount int) {
			ui.source(index, total, path, "lockfile", depCount)
		},
		OnSource: func(index, total int, path string, sourceType audit.SourceType, depCount int) {
			label := "lockfile"
			if sourceType == audit.SourceTypeSBOM {
				label = "SBOM"
			}
			ui.source(index, total, path, label, depCount)
		},
		OnIndex: func(loaded, total int) {
			ui.progress(fmt.Sprintf("Loading malicious package index... %d/%d advisories", loaded, total))
		},
		OnQuery: func(checked, total int, lockfile string) {
			if lockfile != "" {
				ui.progress(fmt.Sprintf("Checking packages... %d/%d | %s",
					checked, total, filepathBase(lockfile)))
				return
			}
			ui.progress(fmt.Sprintf("Checking packages... %d/%d", checked, total))
		},
		OnFinding: func(f audit.Finding) {
			ui.clear()
			if ui.findingCount > 0 {
				writeCardSeparator(cardOut, c)
			}
			ui.findingCount++
			writeAuditFindingCard(cardOpts, f)
		},
		OnStatus:   ui.status,
		OnComplete: ui.complete,
	}
}

type auditProgressUI struct {
	errOut       io.Writer
	c            aurora.Aurora
	verbose      bool
	lastLineLen  int
	findingCount int

	ghTotal    int
	ghCached   int
	ghFetched  int
	ghSkipped  int
	ghCurrent  string
	ghSkipNote []string

	extractIndex   int
	extractTotal   int
	extractDeps    int
	extractWithDep int
}

func (ui *auditProgressUI) prefix() string {
	return ui.c.BrightBlack("[depx] ").String()
}

func (ui *auditProgressUI) clear() {
	if ui.lastLineLen > 0 {
		fmt.Fprintf(ui.errOut, "\r%s\r", strings.Repeat(" ", ui.lastLineLen))
		ui.lastLineLen = 0
	}
}

func (ui *auditProgressUI) line(msg string) {
	ui.clear()
	fmt.Fprintln(ui.errOut, ui.prefix()+msg)
}

func (ui *auditProgressUI) progress(msg string) {
	line := ui.prefix() + msg
	padded := line
	if len(padded) < ui.lastLineLen {
		padded += strings.Repeat(" ", ui.lastLineLen-len(padded))
	}
	fmt.Fprintf(ui.errOut, "\r%s", padded)
	ui.lastLineLen = len(padded)
}

func (ui *auditProgressUI) complete() {
	ui.clear()
}

func (ui *auditProgressUI) source(index, total int, path, label string, depCount int) {
	ui.extractIndex = index
	ui.extractTotal = total
	ui.extractDeps += depCount
	if depCount > 0 {
		ui.extractWithDep++
	}

	ui.progress(fmt.Sprintf("Extracting dependencies... %d/%d (%d packages)",
		index, total, ui.extractDeps))

	if index == total {
		ui.clear()
		ui.line(fmt.Sprintf("Extracted %d packages from %d files (%d with dependencies)",
			ui.extractDeps, total, ui.extractWithDep))
	}
}

func (ui *auditProgressUI) status(msg string) {
	switch {
	case ui.handleGitHubStatus(msg):
		return
	case strings.HasPrefix(msg, "Checking dependencies in "):
		ui.finishGitHubPhase()
		ui.line(msg)
	case strings.HasPrefix(msg, "Loading malicious package index"):
		ui.line("Loading malicious package index...")
	case strings.Contains(msg, "Downloading ") && strings.Contains(msg, "malicious package data"):
		ui.progress(msg)
	case strings.HasPrefix(msg, "Fetching malicious package corpus"):
		ui.progress(msg)
	case strings.HasPrefix(msg, "Malicious package index ready"):
		ui.clear()
		ui.line(msg)
	case strings.HasPrefix(msg, "Checking global installs"):
		ui.line(msg)
	default:
		ui.line(msg)
	}
}

func (ui *auditProgressUI) finishGitHubPhase() {
	if ui.ghTotal == 0 && ui.ghCached+ui.ghFetched+ui.ghSkipped == 0 {
		return
	}
	ui.clear()
	ui.ghCurrent = ""
	ui.line(ui.githubSummary() + " ready")
	for _, note := range ui.ghSkipNote {
		ui.line(note)
	}
	ui.ghCached, ui.ghFetched, ui.ghSkipped, ui.ghTotal = 0, 0, 0, 0
	ui.ghSkipNote = nil
}

func (ui *auditProgressUI) handleGitHubStatus(msg string) bool {
	switch {
	case strings.HasPrefix(msg, "Resolving "):
		var n int
		if _, err := fmt.Sscanf(msg, "Resolving %d GitHub repositories", &n); err == nil {
			ui.ghTotal = n
		}
		ui.line(msg)
		return true
	case strings.HasPrefix(msg, "Using cached SBOM for "):
		ui.ghCached++
		ui.ghCurrent = strings.TrimPrefix(msg, "Using cached SBOM for ")
		ui.refreshGitHub()
		return true
	case strings.HasPrefix(msg, "Fetching SBOM from GitHub for "):
		ui.ghCurrent = strings.TrimSuffix(strings.TrimPrefix(msg, "Fetching SBOM from GitHub for "), "…")
		ui.refreshGitHub()
		return true
	case strings.HasPrefix(msg, "Waiting for GitHub SBOM ("):
		ui.ghCurrent = extractBetweenParens(msg)
		ui.refreshGitHub()
		return true
	case strings.HasPrefix(msg, "SBOM ready for "):
		ui.ghFetched++
		ui.ghCurrent = strings.TrimPrefix(msg, "SBOM ready for ")
		ui.refreshGitHub()
		return true
	case strings.HasPrefix(msg, "SBOM unavailable for "):
		if ui.verbose {
			ui.line(msg)
		}
		return true
	case strings.HasPrefix(msg, "Using cached ") && strings.Contains(msg, " for "):
		if ui.verbose {
			ui.line(msg)
		}
		return true
	case strings.HasPrefix(msg, "Skipping "):
		ui.ghSkipped++
		if ui.verbose {
			ui.line(msg)
		} else if len(ui.ghSkipNote) < 5 {
			ui.ghSkipNote = append(ui.ghSkipNote, msg)
		}
		ui.refreshGitHub()
		return true
	case strings.HasPrefix(msg, "Skipped "):
		if !ui.verbose && ui.ghSkipped > 0 {
			ui.ghSkipNote = append(ui.ghSkipNote, msg)
			return true
		}
		ui.line(msg)
		return true
	default:
		return false
	}
}

func (ui *auditProgressUI) refreshGitHub() {
	ui.progress(ui.githubSummary())
}

func (ui *auditProgressUI) githubSummary() string {
	done := ui.ghCached + ui.ghFetched + ui.ghSkipped
	parts := []string{
		fmt.Sprintf("%d cached", ui.ghCached),
		fmt.Sprintf("%d fetched", ui.ghFetched),
	}
	if ui.ghSkipped > 0 {
		parts = append(parts, fmt.Sprintf("%d skipped", ui.ghSkipped))
	}
	summary := "GitHub repos: " + strings.Join(parts, ", ")
	if ui.ghTotal > 0 {
		summary = fmt.Sprintf("GitHub repos %d/%d — %s", done, ui.ghTotal, strings.Join(parts, ", "))
	}
	if ui.ghCurrent != "" {
		summary += " | " + ui.ghCurrent
	}
	return summary
}

func extractBetweenParens(msg string) string {
	start := strings.Index(msg, "(")
	end := strings.LastIndex(msg, ")")
	if start >= 0 && end > start {
		return msg[start+1 : end]
	}
	return ""
}

func shortenPath(path string, max int) string {
	if len(path) <= max {
		return path
	}
	return "..." + path[len(path)-max+3:]
}

func filepathBase(path string) string {
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[i+1:]
	}
	return path
}
