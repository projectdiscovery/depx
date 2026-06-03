package source

import (
	"github.com/projectdiscovery/depx/internal/osv"
	"github.com/projectdiscovery/depx/internal/registry"
)

// EntryFromVuln builds a display entry from a full OSV record.
func EntryFromVuln(v *osv.Vulnerability) PackageEntry {
	if v == nil {
		return PackageEntry{}
	}
	entry := PackageEntry{IDs: []string{v.ID}}
	EnrichFromVuln(&entry, v)
	return entry
}

// EnrichFromVuln fills display fields on entry from vuln.
func EnrichFromVuln(entry *PackageEntry, vuln *osv.Vulnerability) {
	if entry == nil || vuln == nil {
		return
	}
	entry.Summary = vuln.Summary
	entry.Aliases = append([]string(nil), vuln.Aliases...)
	entry.Withdrawn = vuln.Withdrawn != ""
	if pub := vuln.PublishedTime(); !pub.IsZero() {
		entry.Published = pub
	}
	if mod := vuln.ModifiedTime(); !mod.IsZero() {
		entry.ModifiedAt = mod
	}
	if imp := vuln.ImportedTime(); !imp.IsZero() {
		entry.ImportedAt = imp
	}
	entry.Campaign = vuln.CampaignName()
	if name := vuln.PackageName(); name != "" {
		entry.Name = name
	}
	if eco := vuln.PackageEcosystem(); eco != "" && entry.Ecosystem == "" {
		entry.Ecosystem = eco
	}
	for _, aff := range vuln.Affected {
		if len(aff.Versions) == 1 && entry.Version == "" {
			entry.Version = aff.Versions[0]
			break
		}
	}
	if entry.Name != "" && entry.Ecosystem != "" {
		entry.PackageURL = registry.PackagePageURL(entry.Ecosystem, entry.Name)
	}
}
