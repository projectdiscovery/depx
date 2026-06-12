package malindex

import "strings"

// Vulnerability is the advisory record shape consumed across depx. It is no
// longer fetched from a remote OSV API: records are synthesized locally from
// the inventory index (see MaliciousIndex.Vuln), so only the fields depx
// renders are populated.
type Vulnerability struct {
	ID               string           `json:"id"`
	Summary          string           `json:"summary"`
	Details          string           `json:"details"`
	Modified         string           `json:"modified"`
	Published        string           `json:"published"`
	Withdrawn        string           `json:"withdrawn"`
	Aliases          []string         `json:"aliases"`
	Affected         []Affected       `json:"affected"`
	References       []Reference      `json:"references"`
	DatabaseSpecific DatabaseSpecific `json:"database_specific"`
}

type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type Affected struct {
	Package  *Package `json:"package"`
	Versions []string `json:"versions"`
	Ranges   []Range  `json:"ranges"`
}

type Package struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

type Event struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
}

type QueryRequest struct {
	Package *PackageQuery `json:"package,omitempty"`
	Version string        `json:"version,omitempty"`
}

type PackageQuery struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type QueryResponse struct {
	Vulns []Vulnerability `json:"vulns"`
}

type BatchQueryRequest struct {
	Queries []QueryRequest `json:"queries"`
}

type BatchQueryResponse struct {
	Results []QueryResponse `json:"results"`
}

// IsMaliciousID reports whether an advisory ID denotes a malicious-package
// record (OpenSSF MAL-* or PD GitHub-scan GHSCAN-MAL-*).
func IsMaliciousID(id string) bool {
	id = strings.TrimSpace(id)
	return strings.HasPrefix(id, "MAL-") || strings.HasPrefix(id, "GHSCAN-MAL-")
}

// MaliciousVulns filters a slice down to malicious-package advisories.
func MaliciousVulns(vulns []Vulnerability) []Vulnerability {
	out := make([]Vulnerability, 0, len(vulns))
	for _, v := range vulns {
		if IsMaliciousID(v.ID) {
			out = append(out, v)
		}
	}
	return out
}
