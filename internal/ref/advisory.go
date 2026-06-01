package ref

import (
	"regexp"
	"strings"
)

var advisoryIDPattern = regexp.MustCompile(`(?i)^(MAL|GHSCAN-MAL|GHSA|CVE|GO|PYSEC|RUSTSEC|GMS)-[\w-]+$`)

// IsAdvisoryID reports whether input is an OSV advisory identifier rather than a package ref.
func IsAdvisoryID(input string) bool {
	return advisoryIDPattern.MatchString(strings.TrimSpace(input))
}
