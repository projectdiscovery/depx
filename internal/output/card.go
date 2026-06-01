package output

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/logrusorgru/aurora"

	"github.com/projectdiscovery/depx/internal/check"
	"github.com/projectdiscovery/depx/internal/osv"
	"github.com/projectdiscovery/depx/internal/registry"
	"github.com/projectdiscovery/depx/internal/audit"
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

func writeMaliciousHeader(o Options, id, title string) {
	c := o.color()
	fmt.Fprintf(o.Writer, "%s %s - %s\n",
		c.Bold(c.BrightWhite(fmt.Sprintf("[%s]", id))),
		c.Red("Critical"),
		c.Bold(title),
	)
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

func writeVulnPackageURLs(o Options, c aurora.Aurora, vuln *osv.Vulnerability) {
	if vuln == nil {
		return
	}
	seen := make(map[string]struct{})
	for _, aff := range vuln.Affected {
		if aff.Package == nil || aff.Package.Name == "" {
			continue
		}
		key := aff.Package.Ecosystem + "/" + aff.Package.Name
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		version := ""
		if len(aff.Versions) == 1 {
			version = aff.Versions[0]
		}
		writePackageURLLine(o, c, registry.PackagePageURL(aff.Package.Ecosystem, aff.Package.Name), version)
	}
}

func writeFeedCard(o Options, pkg source.PackageEntry) {
	c := o.color()
	id := primaryID(pkg.IDs)
	title := pkg.Summary
	if title == "" {
		title = fmt.Sprintf("Malicious package %s/%s", pkg.Ecosystem, pkg.Name)
	}

	writeMaliciousHeader(o, id, title)

	ageAt := pkg.Published
	if ageAt.IsZero() {
		ageAt = pkg.ModifiedAt
	}
	fmt.Fprintf(o.Writer, "  %s Priority: %s | %s | Age: %s\n",
		c.Cyan("↳"),
		c.Red("IMMEDIATE"),
		c.Magenta("Supply Chain Attack"),
		c.Yellow(formatAgeUrgency(ageAt)),
	)

	fmt.Fprintf(o.Writer, "  %s Published: %s | Modified: %s",
		c.Cyan("↳"),
		c.BrightWhite(formatTimestamp(pkg.Published)),
		c.BrightWhite(formatTimestamp(pkg.ModifiedAt)),
	)
	if !pkg.ImportedAt.IsZero() {
		fmt.Fprintf(o.Writer, " | Imported: %s", c.BrightWhite(formatTimestamp(pkg.ImportedAt)))
	}
	fmt.Fprintln(o.Writer)

	eco := pkg.Ecosystem + "/" + pkg.Name
	if pkg.Name == "" {
		eco = pkg.Ecosystem
	}
	fmt.Fprintf(o.Writer, "  %s Ecosystem: %s | Withdrawn: %s",
		c.Cyan("↳"),
		c.BrightWhite(eco),
		formatCheckmark(c, pkg.Withdrawn),
	)
	if aliases := truncateList(pkg.Aliases, 2); aliases != "" {
		fmt.Fprintf(o.Writer, " | Aliases: %s", c.BrightWhite(aliases))
	}
	fmt.Fprintln(o.Writer)

	if pkg.PackageURL != "" {
		writePackageURLLine(o, c, pkg.PackageURL, pkg.Version)
	}

	campaign := pkg.Campaign
	if campaign == "" {
		campaign = "unknown"
	}
	fmt.Fprintf(o.Writer, "  %s Campaign: %s | OSV: %s\n",
		c.Cyan("↳"),
		c.BrightWhite(campaign),
		c.BrightBlue(osv.VulnPageURL(id)),
	)
}

func writeAuditFindingCard(o Options, f audit.Finding) {
	c := o.color()
	id := primaryID(f.IDs)
	title := f.Summary
	if title == "" {
		title = fmt.Sprintf("Malicious package %s/%s", f.Ecosystem, f.Name)
	}

	writeMaliciousHeader(o, id, title)

	ageAt := f.Published
	if ageAt.IsZero() {
		ageAt = f.ModifiedAt
	}
	fmt.Fprintf(o.Writer, "  %s Priority: %s | %s | Age: %s\n",
		c.Cyan("↳"),
		c.Red("IMMEDIATE"),
		c.Magenta("Supply Chain Attack"),
		c.Yellow(formatAgeUrgency(ageAt)),
	)

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

func writeCheckCard(o Options, result check.Result) {
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

	for _, adv := range result.Advisories {
		writeAdvisoryTimestamps(o, c, adv.PublishedAt, adv.ModifiedAt)
		if adv.URL != "" {
			writeAdvisoryOSVLine(o, c, adv.URL)
		}
		writeAdvisoryReferences(o, c, referenceURLsFromCheck(adv.References))
	}
}

func writeIDCard(o Options, vuln *osv.Vulnerability) {
	c := o.color()
	title := vuln.Summary
	if title == "" {
		title = vuln.ID
	}

	fmt.Fprintf(o.Writer, "%s %s - %s\n",
		c.Bold(c.BrightWhite(fmt.Sprintf("[%s]", vuln.ID))),
		c.Red("MALICIOUS"),
		c.Bold(title),
	)

	writeVulnPackageURLs(o, c, vuln)

	writeAdvisoryTimestamps(o, c, vuln.Published, vuln.Modified)
	writeAdvisoryOSVLine(o, c, osv.VulnPageURL(vuln.ID))
	writeAdvisoryReferences(o, c, referenceURLsFromVuln(vuln.References))
}

func writeAdvisoryTimestamps(o Options, c aurora.Aurora, published, modified string) {
	if published == "" && modified == "" {
		return
	}
	fmt.Fprintf(o.Writer, "  %s Published: %s | Modified: %s\n",
		c.Cyan("↳"),
		c.BrightWhite(formatOSVTimeWithAge(published)),
		c.BrightWhite(formatOSVTimeWithAge(modified)),
	)
}

func writeAdvisoryOSVLine(o Options, c aurora.Aurora, url string) {
	if url == "" {
		return
	}
	fmt.Fprintf(o.Writer, "  %s OSV: %s\n", c.Cyan("↳"), c.BrightBlue(url))
}

func writeAdvisoryReferences(o Options, c aurora.Aurora, refs []string) {
	if refs := truncateList(refs, 2); refs != "" {
		fmt.Fprintf(o.Writer, "  %s References: %s\n", c.Cyan("↳"), c.BrightWhite(refs))
	}
}

func referenceURLsFromCheck(refs []check.AdvisoryReference) []string {
	urls := make([]string, 0, len(refs))
	for _, ref := range refs {
		if ref.URL != "" {
			urls = append(urls, ref.URL)
		}
	}
	return urls
}

func referenceURLsFromVuln(refs []osv.Reference) []string {
	urls := make([]string, 0, len(refs))
	for _, ref := range refs {
		if ref.URL != "" {
			urls = append(urls, ref.URL)
		}
	}
	return urls
}

func defaultStr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
