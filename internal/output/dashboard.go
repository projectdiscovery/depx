package output

import (
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/logrusorgru/aurora"

	"github.com/projectdiscovery/depx/internal/feed"
	"github.com/projectdiscovery/depx/internal/source"
)

const (
	dashboardBarWidth   = 36
	dashboardIndent     = "  "
	dashboardLabelWidth = 18
	dashboardRuleWidth  = 64
)

func RenderFeedWithDashboard(o Options, version string, result *feed.Result) error {
	if o.JSON {
		return WriteJSON(o.Writer, version, "feed", result)
	}
	c := o.color()
	writeFeedDashboard(o.Writer, c, result)
	return nil
}

func writeFeedList(o Options, c aurora.Aurora, result *feed.Result) {
	for _, pkg := range result.Packages {
		writeFeedCardHeaderOnly(o, pkg)
	}
	suffix := fmt.Sprintf("(published in last %s)", result.Since)
	if result.Ecosystem != "" {
		suffix = fmt.Sprintf("(published in last %s, ecosystem: %s)", result.Since, result.Ecosystem)
	}
	writeCardFooter(o.Writer, c, result.Shown, result.Total, suffix)
}

func writeFeedCards(o Options, c aurora.Aurora, result *feed.Result) {
	writeSectionHeader(o.Writer, c, "latest malicious packages", "sorted by published date")
	fmt.Fprintln(o.Writer)
	for i, pkg := range result.Packages {
		if i > 0 {
			writeCardSeparator(o.Writer, c)
		}
		writeFeedCard(o, pkg)
	}
	suffix := fmt.Sprintf("(published in last %s)", result.Since)
	if result.Ecosystem != "" {
		suffix = fmt.Sprintf("(published in last %s, ecosystem: %s)", result.Since, result.Ecosystem)
	}
	writeCardFooter(o.Writer, c, result.Shown, result.Total, suffix)
}

func writeFeedDashboard(w io.Writer, c aurora.Aurora, result *feed.Result) {
	writeSectionHeader(w, c, "Malicious package & supply-chain intelligence", "")

	scope := fmt.Sprintf("published in last %s", result.Since)
	if result.Ecosystem != "" {
		scope += " · " + result.Ecosystem
	}
	advisoryLabel := "advisories"
	if result.Window.Advisories == 1 {
		advisoryLabel = "advisory"
	}
	scope += fmt.Sprintf(" · %d %s", result.Window.Advisories, advisoryLabel)
	writeSubHeader(w, c, "activity", scope)
	fmt.Fprintln(w)

	if len(result.Window.Ecosystems) > 0 {
		writeSubHeader(w, c, "top ecosystems", "")
		writeCountBars(w, c, result.Window.Ecosystems)
		fmt.Fprintln(w)
	}

	if len(result.Window.Namespaces) > 0 {
		writeSubHeader(w, c, "most impacted namespaces", "by scope/org")
		writeCountBars(w, c, result.Window.Namespaces)
		fmt.Fprintln(w)
	}

	if result.Window.Advisories > 0 {
		writeSubHeader(w, c, "disclosure age", "by published date")
		writeCountBars(w, c, result.Window.Age)
		fmt.Fprintln(w)
	}

	if result.Window.WithAliases > 0 {
		writeSubHeader(w, c, "window status", "")
		writeKV(w, c, "with GHSA alias", fmt.Sprintf("%d", result.Window.WithAliases))
		fmt.Fprintln(w)
	}

	writeSubHeader(w, c, "quick start", "")
	quick := [][2]string{
		{"depx feed", "recently published malicious packages"},
		{"depx audit", "audit the system for malicious packages"},
		{"depx github", "audit your private GitHub repos for malicious packages"},
		{"depx github google", "hunt for malicious packages in a given GitHub org"},
	}
	cmdWidth := 0
	for _, q := range quick {
		if l := len(q[0]); l > cmdWidth {
			cmdWidth = l
		}
	}
	for _, q := range quick {
		fmt.Fprintf(w, "%s%s  %s\n",
			dashboardIndent,
			c.BrightWhite(padRight(q[0], cmdWidth)),
			c.BrightBlack("# "+q[1]),
		)
	}
}

func writeSectionHeader(w io.Writer, c aurora.Aurora, title, subtitle string) {
	rule := strings.Repeat("─", dashboardRuleWidth)
	fmt.Fprintln(w, c.BrightBlack(rule))
	if subtitle != "" {
		fmt.Fprintf(w, "%s  %s\n", c.Bold(c.BrightWhite(title)), c.BrightBlack(subtitle))
	} else {
		fmt.Fprintln(w, c.Bold(c.BrightWhite(title)))
	}
	fmt.Fprintln(w, c.BrightBlack(rule))
	fmt.Fprintln(w)
}

func writeSubHeader(w io.Writer, c aurora.Aurora, title, note string) {
	if note != "" {
		fmt.Fprintf(w, "%s %s\n", c.Bold(title), c.BrightBlack("· "+note))
	} else {
		fmt.Fprintf(w, "%s\n", c.Bold(title))
	}
}

func writeKV(w io.Writer, c aurora.Aurora, label, value string) {
	fmt.Fprintf(w, "%s%s  %s\n",
		dashboardIndent,
		c.BrightBlack(padRight(label, dashboardLabelWidth)),
		c.BrightWhite(value),
	)
}

func writeCountBars(w io.Writer, c aurora.Aurora, buckets []source.CountBucket) {
	if len(buckets) == 0 {
		return
	}
	maxLabel, maxCount := 0, 0
	for _, b := range buckets {
		if l := utf8.RuneCountInString(b.Label); l > maxLabel {
			maxLabel = l
		}
		if c := len(fmt.Sprintf("%d", b.Count)); c > maxCount {
			maxCount = c
		}
	}
	for _, b := range buckets {
		fmt.Fprintf(w, "%s%s  %s  %s  %s\n",
			dashboardIndent,
			c.BrightWhite(padRight(b.Label, maxLabel)),
			renderBar(c, b.Share, dashboardBarWidth),
			c.BrightWhite(padLeft(fmt.Sprintf("%d", b.Count), maxCount)),
			c.BrightBlack(fmt.Sprintf("%6s", source.FormatShare(b.Share))),
		)
	}
}

func renderBar(c aurora.Aurora, share float64, width int) string {
	filled := int(share/100*float64(width) + 0.5)
	if filled == 0 && share > 0 {
		filled = 1
	}
	if filled > width {
		filled = width
	}
	bar := strings.Repeat("█", filled)
	track := strings.Repeat("·", width-filled)
	return c.Cyan(bar).String() + c.BrightBlack(track).String()
}

func padRight(s string, width int) string {
	n := width - utf8.RuneCountInString(s)
	if n <= 0 {
		return s
	}
	return s + strings.Repeat(" ", n)
}

func padLeft(s string, width int) string {
	n := width - utf8.RuneCountInString(s)
	if n <= 0 {
		return s
	}
	return strings.Repeat(" ", n) + s
}
