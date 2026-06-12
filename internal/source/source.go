package source

import "time"

type PackageEntry struct {
	Ecosystem   string    `json:"ecosystem"`
	Name        string    `json:"name"`
	Version     string    `json:"version,omitempty"`
	PackageURL  string    `json:"registry_url,omitempty"`
	IDs         []string  `json:"ids"`
	Aliases     []string  `json:"aliases,omitempty"`
	ModifiedAt  time.Time `json:"modified_at"`
	Published   time.Time `json:"published_at,omitempty"`
	ImportedAt  time.Time `json:"imported_at,omitempty"`
	Summary     string    `json:"summary,omitempty"`
	Withdrawn   bool      `json:"withdrawn"`
	Quarantined bool      `json:"quarantined,omitempty"`
}
