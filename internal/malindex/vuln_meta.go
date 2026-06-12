package malindex

import (
	"errors"
	"os"
	"strings"
	"time"
)

func parseOSVTime(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, errors.New("empty time")
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t.UTC(), nil
	}
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

type MaliciousOrigin struct {
	ImportTime   string `json:"import_time"`
	ModifiedTime string `json:"modified_time"`
	Source       string `json:"source"`
}

type DatabaseSpecific struct {
	MaliciousPackagesOrigins []MaliciousOrigin `json:"malicious-packages-origins"`
}

func (v *Vulnerability) PublishedTime() time.Time {
	t, _ := parseOSVTime(v.Published)
	return t
}

func (v *Vulnerability) ModifiedTime() time.Time {
	t, _ := parseOSVTime(v.Modified)
	return t
}

func (v *Vulnerability) ImportedTime() time.Time {
	for _, origin := range v.DatabaseSpecific.MaliciousPackagesOrigins {
		if t, err := parseOSVTime(origin.ImportTime); err == nil {
			return t
		}
	}
	return time.Time{}
}

func (v *Vulnerability) PackageName() string {
	for _, aff := range v.Affected {
		if aff.Package != nil && aff.Package.Name != "" {
			return aff.Package.Name
		}
	}
	return ""
}

func (v *Vulnerability) PackageEcosystem() string {
	for _, aff := range v.Affected {
		if aff.Package != nil && aff.Package.Ecosystem != "" {
			return aff.Package.Ecosystem
		}
	}
	return ""
}

const defaultVulnPageBase = "https://osv.dev/vulnerability"

// VulnPageURL returns the public OSV advisory page for an ID.
func VulnPageURL(id string) string {
	if base := os.Getenv("DEPX_OSV_VULN_URL"); base != "" {
		return strings.TrimRight(base, "/") + "/" + id
	}
	return defaultVulnPageBase + "/" + id
}
