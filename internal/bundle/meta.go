package bundle

import "time"

const metaSchemaVersion = 1

// Meta describes an embedded offline intel bundle.
type Meta struct {
	SchemaVersion int       `json:"schema_version"`
	Source        string    `json:"source"`
	BuiltAt       time.Time `json:"built_at"`
	EntryCount    int       `json:"entry_count,omitempty"`
	PackageCount  int       `json:"package_count,omitempty"`
}
