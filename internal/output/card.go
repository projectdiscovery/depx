package output

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/logrusorgru/aurora"

	"github.com/projectdiscovery/depx/internal/audit"
	"github.com/projectdiscovery/depx/internal/check"
	"github.com/projectdiscovery/depx/internal/osv"
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

// writeMaliciousCardHeader prints a single scannable line: advisory id, severity,
// package (name emphasized), and disclosure age. The OSV summary title is omitted
// here because it usually repeats the package name.
func writeMaliciousCardHeader(o Options, id, ecosystem, name string, ageAt time.Time) {
	c := o.color()
	fmt.Fprintf(o.Writer, "%s %s · %s · %s\n",
		c.Bold(c.BrightWhite(fmt.Sprintf("[%s]", id))),
		c.Red("Critical"),
		formatPackageHeader(c, ecosystem, name),
		c.Yellow(formatAgeUrgency(ageAt)),
	)
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
	switch {
	case days <= 7:
		return fmt.Sprintf("%dd (NEW)", days)
	case days <= 30:
		return fmt.Sprintf("%dd (RECENT)", days)
	default:
		return fmt.Sprintf("%dd", days)
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

func formatTimestampWithAge(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	t = t.UTC()
	return fmt.Sprintf("%s (%dd)", t.Format("2006-01-02"), daysSince(t))
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

func formatCheckmark(c aurora.Aurora, ok bool) string {
	if ok {
		return c.Green("✔").String()
	}
	return c.Red("✘").String()
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

func formatTimestamp(t time.Time) string {
	return formatTimestampWithAge(t)
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
	ageAt := pkg.Published
	writeMaliciousCardHeader(o, id, pkg.Ecosystem, pkg.Name, ageAt)
}

func writeFeedCard(o Options, pkg source.PackageEntry) {
	c := o.color()
	id := primaryID(pkg.IDs)

	ageAt := pkg.Published
	writeMaliciousCardHeader(o, id, pkg.Ecosystem, pkg.Name, ageAt)

	fmt.Fprintf(o.Writer, "  %s Published: %s | Modified: %s",
		c.Cyan("↳"),
		c.BrightWhite(formatTimestamp(pkg.Published)),
		c.BrightWhite(formatTimestamp(pkg.ModifiedAt)),
	)
	if !pkg.ImportedAt.IsZero() {
		fmt.Fprintf(o.Writer, " | Imported: %s", c.BrightWhite(formatTimestamp(pkg.ImportedAt)))
	}
	fmt.Fprintln(o.Writer)

	if pkg.PackageURL != "" {
		writePackageURLLine(o, c, pkg.PackageURL, pkg.Version)
	}

	fmt.Fprintf(o.Writer, "  %s Withdrawn: %s | OSV: %s",
		c.Cyan("↳"),
		formatCheckmark(c, pkg.Withdrawn),
		c.BrightBlue(osv.VulnPageURL(id)),
	)
	if aliases := truncateList(pkg.Aliases, 2); aliases != "" {
		fmt.Fprintf(o.Writer, " | Aliases: %s", c.BrightWhite(aliases))
	}
	fmt.Fprintln(o.Writer)
}

func writeAuditFindingCard(o Options, f audit.Finding) {
	c := o.color()
	id := primaryID(f.IDs)

	ageAt := f.Published
	writeMaliciousCardHeader(o, id, f.Ecosystem, f.Name, ageAt)

	if !f.Published.IsZero() || !f.ModifiedAt.IsZero() {
		fmt.Fprintf(o.Writer, "  %s Published: %s | Modified: %s\n",
			c.Cyan("↳"),
			c.BrightWhite(formatTimestamp(f.Published)),
			c.BrightWhite(formatTimestamp(f.ModifiedAt)),
		)
	}

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

	campaign := f.Campaign
	if campaign == "" {
		campaign = "unknown"
	}
	fmt.Fprintf(o.Writer, "  %s Campaign: %s | OSV: %s\n",
		c.Cyan("↳"),
		c.BrightWhite(campaign),
		c.BrightBlue(osv.VulnPageURL(id)),
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
		Ecosystem:  result.PackageEcosystem,
		Name:       result.PackageName,
		Version:    result.PackageVersion,
		PackageURL: result.PackageURL,
		IDs:        append([]string(nil), result.IDs...),
		Campaign:   result.Campaign,
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
	if result.Verdict == check.VerdictMalicious {
		writeFeedCard(o, packageEntryFromCheck(result))
		return
	}
	writeNonMaliciousCheckCard(o, result)
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

func writeIDCard(o Options, vuln *osv.Vulnerability) {
	writeFeedCard(o, source.EntryFromVuln(vuln))
}
