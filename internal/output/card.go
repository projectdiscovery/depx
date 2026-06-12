package output

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/logrusorgru/aurora"

	"github.com/projectdiscovery/depx/internal/audit"
	"github.com/projectdiscovery/depx/internal/check"
	"github.com/projectdiscovery/depx/internal/malindex"
	"github.com/projectdiscovery/depx/internal/registry"
	"github.com/projectdiscovery/depx/internal/source"
)

const cardSeparator = "─────────────────────────────────────────────────────────────────────────"

func writeCardSeparator(w io.Writer, c aurora.Aurora) {
	fmt.Fprintln(w, c.BrightBlack(cardSeparator))
	fmt.Fprintln(w)
}

func writeCardFooter(w io.Writer, c aurora.Aurora, shown, total int, suffix string) {
	msg := fmt.Sprintf("↳ Showing %d of %d total results", shown, total)
	if suffix != "" {
		msg += " " + suffix
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, c.BrightBlue(msg))
	fmt.Fprintln(w)
}

// writePackageCardHeader prints a single scannable line: advisory id, verdict,
// package (name emphasized), and optional disclosure age.
func writePackageCardHeader(o Options, id, ecosystem, name string, ageAt time.Time, quarantined, showAge bool) {
	c := o.color()
	if showAge && !ageAt.IsZero() {
		fmt.Fprintf(o.Writer, "%s %s · %s · %s\n",
			c.Bold(c.BrightWhite(fmt.Sprintf("[%s]", id))),
			packageVerdictLabel(c, quarantined),
			formatPackageHeader(c, ecosystem, name),
			c.Yellow(formatAgeUrgency(ageAt)),
		)
		return
	}
	fmt.Fprintf(o.Writer, "%s %s · %s\n",
		c.Bold(c.BrightWhite(fmt.Sprintf("[%s]", id))),
		packageVerdictLabel(c, quarantined),
		formatPackageHeader(c, ecosystem, name),
	)
}

func packageVerdictLabel(c aurora.Aurora, quarantined bool) string {
	if quarantined {
		return quarantineVerdictStyle(c, "QUARANTINED")
	}
	return c.Red("MALICIOUS").String()
}

func entryQuarantined(pkg source.PackageEntry) bool {
	return pkg.Quarantined
}

func findingQuarantined(f audit.Finding) bool {
	return f.Verdict == check.VerdictQuarantined
}

func formatPackageHeader(c aurora.Aurora, ecosystem, name string) string {
	eco := strings.TrimSpace(ecosystem)
	n := strings.TrimSpace(name)
	switch {
	case n == "" && eco == "":
		return c.Bold(c.BrightWhite("unknown package")).String()
	case n == "":
		return c.Bold(c.BrightWhite(eco)).String()
	case eco == "":
		return c.Bold(c.BrightWhite(n)).String()
	default:
		return c.Bold(c.BrightWhite(n)).String() + c.BrightBlack(" ("+eco+")").String()
	}
}

func formatAgeUrgency(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	days := daysSince(t)
	age := formatRelativeAge(t)
	switch {
	case days <= 7:
		return fmt.Sprintf("%s (NEW)", age)
	case days <= 30:
		return fmt.Sprintf("%s (RECENT)", age)
	default:
		return age
	}
}

func daysSince(t time.Time) int {
	if t.IsZero() {
		return -1
	}
	days := int(time.Since(t.UTC()).Hours() / 24)
	if days < 0 {
		return 0
	}
	return days
}

// formatRelativeAge renders human-readable age: days when >=24h, otherwise hours.
func formatRelativeAge(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	elapsed := time.Since(t.UTC())
	if elapsed < 0 {
		elapsed = 0
	}
	if days := int(elapsed.Hours() / 24); days >= 1 {
		return fmt.Sprintf("%dd", days)
	}
	hours := int(elapsed.Hours())
	if hours < 1 {
		hours = 1
	}
	return fmt.Sprintf("%dh", hours)
}

func formatTimestampWithAge(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	t = t.UTC()
	return fmt.Sprintf("%s (%s)", t.Format("2006-01-02"), formatRelativeAge(t))
}

func formatOSVTimeWithAge(raw string) string {
	if raw == "" {
		return "unknown"
	}
	t, ok := parseCardTime(raw)
	if !ok {
		return raw
	}
	return formatTimestampWithAge(t)
}

func parseCardTime(raw string) (time.Time, bool) {
	if raw == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t.UTC(), true
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

func truncateList(items []string, max int) string {
	if len(items) == 0 {
		return ""
	}
	if len(items) <= max {
		return strings.Join(items, ", ")
	}
	visible := strings.Join(items[:max], ", ")
	return fmt.Sprintf("%s +%d", visible, len(items)-max)
}

func primaryID(ids []string) string {
	if len(ids) == 0 {
		return "UNKNOWN"
	}
	return ids[0]
}

func writePackageURLLine(o Options, c aurora.Aurora, packageURL, version string) {
	if packageURL == "" {
		return
	}
	line := packageURL
	if version != "" {
		line += " (" + version + ")"
	}
	fmt.Fprintf(o.Writer, "  %s Package: %s\n", c.Cyan("↳"), c.BrightBlue(line))
}

func writeCheckPackageURLs(o Options, c aurora.Aurora, result check.Result) {
	if result.PackageURL != "" {
		writePackageURLLine(o, c, result.PackageURL, result.PackageVersion)
		return
	}
	if result.PackageName == "" {
		return
	}
	ecos := result.MatchedEcosystems
	if len(ecos) == 0 && result.PackageEcosystem != "" {
		ecos = []string{result.PackageEcosystem}
	}
	for _, eco := range ecos {
		writePackageURLLine(o, c, registry.PackagePageURL(eco, result.PackageName), result.PackageVersion)
	}
}

// writeFeedCardHeaderOnly prints just the one-line card header for --list mode.
func writeFeedCardHeaderOnly(o Options, pkg source.PackageEntry) {
	id := primaryID(pkg.IDs)
	writePackageCardHeader(o, id, pkg.Ecosystem, pkg.Name, pkg.Published, entryQuarantined(pkg), true)
}

func writeFeedCard(o Options, pkg source.PackageEntry) {
	c := o.color()
	id := primaryID(pkg.IDs)
	quarantined := entryQuarantined(pkg)

	writePackageCardHeader(o, id, pkg.Ecosystem, pkg.Name, pkg.Published, quarantined, true)

	// Disclosure age is already shown in the card header, so the timestamp
	// line (Published / Modified / Imported) is redundant and omitted.

	if pkg.PackageURL != "" {
		writePackageURLLine(o, c, pkg.PackageURL, pkg.Version)
	}

	fmt.Fprintf(o.Writer, "  %s OSV: %s",
		c.Cyan("↳"),
		c.BrightBlue(malindex.VulnPageURL(id)),
	)
	if aliases := truncateList(pkg.Aliases, 2); aliases != "" {
		fmt.Fprintf(o.Writer, " | Aliases: %s", c.BrightWhite(aliases))
	}
	fmt.Fprintln(o.Writer)
}

func writeAuditFindingCard(o Options, f audit.Finding) {
	c := o.color()
	id := primaryID(f.IDs)
	quarantined := findingQuarantined(f)

	writePackageCardHeader(o, id, f.Ecosystem, f.Name, f.Published, quarantined, true)

	// Disclosure age is shown in the card header; the Published / Modified line
	// is redundant and omitted.

	if path := findingSourcePath(f); path != "" {
		fmt.Fprintf(o.Writer, "  %s %s: %s\n",
			c.Cyan("↳"),
			findingSourceLabel(f),
			c.BrightWhite(path),
		)
	}

	if dep := formatFindingDependency(f); dep != "" {
		fmt.Fprintf(o.Writer, "  %s Dependency: %s\n",
			c.Cyan("↳"),
			c.BrightWhite(dep),
		)
	}

	if f.ProjectURL != "" {
		fmt.Fprintf(o.Writer, "  %s Project: %s\n",
			c.Cyan("↳"),
			c.BrightBlue(f.ProjectURL),
		)
	} else if f.ProjectDir != "" {
		fmt.Fprintf(o.Writer, "  %s Project: %s\n",
			c.Cyan("↳"),
			c.BrightWhite(f.ProjectDir),
		)
	}

	if f.PackageURL != "" {
		writePackageURLLine(o, c, f.PackageURL, f.Version)
	}

	fmt.Fprintf(o.Writer, "  %s OSV: %s\n",
		c.Cyan("↳"),
		c.BrightBlue(malindex.VulnPageURL(id)),
	)
}

func formatFindingDependency(f audit.Finding) string {
	if f.Name == "" {
		return ""
	}
	eco := f.Ecosystem
	if eco == "" {
		eco = "unknown"
	}
	line := eco + "/" + f.Name
	if f.Version != "" {
		line += "@" + f.Version
	}
	return line
}

func findingSourcePath(f audit.Finding) string {
	if f.Source != "" {
		return f.Source
	}
	return f.Lockfile
}

func findingSourceLabel(f audit.Finding) string {
	if f.SourceType == string(audit.SourceTypeSBOM) {
		return "SBOM"
	}
	return "Lockfile"
}

func packageEntryFromCheck(result check.Result) source.PackageEntry {
	entry := source.PackageEntry{
		Ecosystem:   result.PackageEcosystem,
		Name:        result.PackageName,
		Version:     result.PackageVersion,
		PackageURL:  result.PackageURL,
		IDs:         append([]string(nil), result.IDs...),
		Quarantined: result.Verdict == check.VerdictQuarantined,
	}
	if entry.Ecosystem == "" && len(result.MatchedEcosystems) > 0 {
		entry.Ecosystem = result.MatchedEcosystems[0]
	}
	if len(result.Advisories) > 0 {
		adv := result.Advisories[0]
		if entry.Summary == "" {
			entry.Summary = adv.Summary
		}
		if pub, ok := parseCardTime(adv.PublishedAt); ok {
			entry.Published = pub
		}
		if mod, ok := parseCardTime(adv.ModifiedAt); ok {
			entry.ModifiedAt = mod
		}
	}
	if entry.PackageURL == "" && entry.Name != "" && entry.Ecosystem != "" {
		entry.PackageURL = registry.PackagePageURL(entry.Ecosystem, entry.Name)
	}
	return entry
}

func writeCheckCard(o Options, result check.Result) {
	switch result.Verdict {
	case check.VerdictMalicious, check.VerdictQuarantined:
		writeFeedCard(o, packageEntryFromCheck(result))
	default:
		writeNonMaliciousCheckCard(o, result)
	}
}

func writeNonMaliciousCheckCard(o Options, result check.Result) {
	c := o.color()
	id := primaryID(result.IDs)
	if id == "UNKNOWN" {
		id = result.Ref
	}

	title := result.Ref
	if len(result.Advisories) > 0 && result.Advisories[0].Summary != "" {
		title = result.Advisories[0].Summary
	}

	fmt.Fprintf(o.Writer, "%s %s - %s\n",
		c.Bold(c.BrightWhite(fmt.Sprintf("[%s]", id))),
		verdictLabel(c, result.Verdict),
		c.Bold(title),
	)

	if len(result.MatchedEcosystems) > 0 {
		fmt.Fprintf(o.Writer, "  %s Matched: %s | Checked: %s\n",
			c.Cyan("↳"),
			c.BrightWhite(strings.Join(result.MatchedEcosystems, ", ")),
			c.BrightWhite(strings.Join(result.CheckedEcosystems, ", ")),
		)
	} else if len(result.CheckedEcosystems) > 0 {
		fmt.Fprintf(o.Writer, "  %s Checked: %s\n",
			c.Cyan("↳"),
			c.BrightWhite(strings.Join(result.CheckedEcosystems, ", ")),
		)
	}

	if result.Verdict == check.VerdictNotFound {
		fmt.Fprintf(o.Writer, "  %s Package not found in any checked ecosystem\n",
			c.Cyan("↳"),
		)
	} else if len(result.FoundEcosystems) > 0 {
		fmt.Fprintf(o.Writer, "  %s Found: %s\n",
			c.Cyan("↳"),
			c.BrightWhite(strings.Join(result.FoundEcosystems, ", ")),
		)
	}

	writeCheckPackageURLs(o, c, result)

	if result.Registry != nil && result.Registry.Yanked {
		fmt.Fprintf(o.Writer, "  %s Registry: %s | Status: %s\n",
			c.Cyan("↳"),
			c.Yellow("yanked"),
			c.BrightWhite(result.Registry.Status),
		)
	}
}

func writeIDCard(o Options, vuln *malindex.Vulnerability) {
	writeFeedCard(o, source.EntryFromVuln(vuln))
}
