package output

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/logrusorgru/aurora"

	"github.com/projectdiscovery/depx/internal/audit"
	"github.com/projectdiscovery/depx/internal/osv"
)

// NewAuditProgress builds the audit progress reporter and a stop function. The
// stop function halts the background activity animator and clears the transient
// line; callers must invoke it before rendering final results to stdout.
func NewAuditProgress(o Options, verbose bool) (*audit.Progress, func()) {
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
		errOut:      errOut,
		c:           c,
		verbose:     verbose,
		interactive: isInteractive(errOut),
	}
	cardOpts := Options{Writer: cardOut, NoColor: o.NoColor}

	prog := &audit.Progress{
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
			ui.progress(osv.FormatIndexDownloadProgress(loaded, total))
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
	return prog, ui.stop
}

type auditProgressUI struct {
	errOut       io.Writer
	c            aurora.Aurora
	verbose      bool
	interactive  bool
	findingCount int

	// mu guards the transient-line render state shared between the audit
	// goroutine (callbacks) and the background animator goroutine.
	mu          sync.Mutex
	lastLineLen int
	transient   string
	glyph       int
	animStarted bool
	animStop    chan struct{}
	animDone    chan struct{}

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
	ui.mu.Lock()
	ui.transient = ""
	ui.clearLocked()
	ui.mu.Unlock()
}

func (ui *auditProgressUI) clearLocked() {
	if ui.lastLineLen > 0 {
		fmt.Fprintf(ui.errOut, "\r%s\r", strings.Repeat(" ", ui.lastLineLen))
		ui.lastLineLen = 0
	}
}

func (ui *auditProgressUI) line(msg string) {
	ui.mu.Lock()
	ui.transient = ""
	ui.clearLocked()
	fmt.Fprintln(ui.errOut, ui.prefix()+msg)
	ui.mu.Unlock()
}

func (ui *auditProgressUI) progress(msg string) {
	ui.mu.Lock()
	ui.transient = msg
	ui.startAnimLocked()
	ui.renderTransientLocked()
	ui.mu.Unlock()
}

// renderTransientLocked redraws the current transient message. On interactive
// terminals it is prefixed with an animated spinner glyph; non-interactive
// output is left byte-identical to the pre-spinner behavior.
func (ui *auditProgressUI) renderTransientLocked() {
	if ui.transient == "" {
		return
	}
	line := ui.prefix()
	if ui.interactive {
		line += ui.c.Cyan(spinnerFrames[ui.glyph%len(spinnerFrames)]).String() + " "
	}
	line += ui.transient
	if len(line) < ui.lastLineLen {
		line += strings.Repeat(" ", ui.lastLineLen-len(line))
	}
	fmt.Fprintf(ui.errOut, "\r%s", line)
	ui.lastLineLen = len(line)
}

func (ui *auditProgressUI) startAnimLocked() {
	if !ui.interactive || ui.animStarted {
		return
	}
	ui.animStarted = true
	ui.animStop = make(chan struct{})
	ui.animDone = make(chan struct{})
	go ui.animate()
}

func (ui *auditProgressUI) animate() {
	defer close(ui.animDone)
	ticker := time.NewTicker(spinnerInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ui.animStop:
			return
		case <-ticker.C:
			ui.mu.Lock()
			if ui.transient != "" {
				ui.glyph++
				ui.renderTransientLocked()
			}
			ui.mu.Unlock()
		}
	}
}

// stop halts the animator (if running) and clears the transient line. It is
// safe to call when no animator ever started.
func (ui *auditProgressUI) stop() {
	ui.mu.Lock()
	if !ui.animStarted {
		ui.transient = ""
		ui.clearLocked()
		ui.mu.Unlock()
		return
	}
	stopCh, doneCh := ui.animStop, ui.animDone
	ui.animStarted = false
	ui.mu.Unlock()

	close(stopCh)
	<-doneCh

	ui.mu.Lock()
	ui.transient = ""
	ui.clearLocked()
	ui.mu.Unlock()
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
