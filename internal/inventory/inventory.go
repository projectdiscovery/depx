// Package inventory fetches the ProjectDiscovery malicious-package inventory:
// a single gzipped JSON export that is the sole intel source for depx. The
// export is refreshed hourly upstream and served unauthenticated, so depx
// downloads it whole, decompresses it on the fly, and builds a local index.
package inventory

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// DefaultSourceURL is the unauthenticated, hourly-refreshed inventory export.
const DefaultSourceURL = "https://github.projectdiscovery.io/github/malicious/export"

// SourceURL returns the inventory export URL, allowing an override via
// DEPX_SOURCE_URL for tests and self-hosted mirrors.
func SourceURL() string {
	if v := strings.TrimSpace(os.Getenv("DEPX_SOURCE_URL")); v != "" {
		return v
	}
	return DefaultSourceURL
}

// PackagePageURL returns the public ProjectDiscovery page for a malicious
// advisory/package ID. It is derived from the configured source URL so a
// mirror override stays internally consistent.
func PackagePageURL(id string) string {
	base := strings.TrimSuffix(SourceURL(), "/export")
	return base + "/packages/" + id
}

// IOCs holds indicators of compromise associated with a malicious package.
type IOCs struct {
	Domains    []string `json:"domains,omitempty"`
	FileHashes []string `json:"file_hashes,omitempty"`
	PkgHashes  []string `json:"pkg_hashes,omitempty"`
}

// Record is a single malicious-package entry from the inventory export.
type Record struct {
	Ecosystem        string
	Name             string
	PackageURL       string
	PURL             string
	IDs              []string
	Source           string
	Severity         string
	AllVersions      bool
	AffectedVersions []string
	Summary          string
	References       []string
	IOCs             IOCs
	ModifiedAt       time.Time
	PublishedAt      time.Time
	ImportedAt       time.Time
}

// PrimaryID returns the first advisory ID, or "" when none are present.
func (r Record) PrimaryID() string {
	if len(r.IDs) == 0 {
		return ""
	}
	return r.IDs[0]
}

// Snapshot carries inventory metadata captured during a fetch.
type Snapshot struct {
	SchemaVersion string
	GeneratedAt   time.Time
	Source        string
	ETag          string
	NotModified   bool
}

// Fetch downloads the inventory export and streams every record to onRecord.
//
// The whole document is never held in memory: the gzip body is decoded
// incrementally so peak usage is bounded by the compiled index, not the
// ~125 MB decompressed JSON. When prevETag matches the server's current
// revision the call returns early with Snapshot.NotModified set and onRecord
// is not invoked. The caller is responsible for an appropriate ctx deadline;
// no per-request timeout is imposed here so large transfers are not truncated.
func Fetch(ctx context.Context, url, userAgent, prevETag string, onRecord func(Record) error) (Snapshot, error) {
	if url == "" {
		url = SourceURL()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Snapshot{}, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/gzip")
	if prevETag != "" {
		req.Header.Set("If-None-Match", prevETag)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Snapshot{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotModified {
		return Snapshot{ETag: prevETag, NotModified: true}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return Snapshot{}, fmt.Errorf("inventory fetch %s: status %d", url, resp.StatusCode)
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return Snapshot{}, fmt.Errorf("inventory decompress: %w", err)
	}
	defer func() { _ = gz.Close() }()

	snap := Snapshot{ETag: strings.TrimSpace(resp.Header.Get("ETag"))}
	if err := decodeStream(gz, &snap, onRecord); err != nil {
		return Snapshot{}, err
	}
	return snap, nil
}

func decodeStream(r io.Reader, snap *Snapshot, onRecord func(Record) error) error {
	dec := json.NewDecoder(r)
	if _, err := dec.Token(); err != nil { // opening '{'
		return fmt.Errorf("inventory decode: %w", err)
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("inventory decode: %w", err)
		}
		key, _ := keyTok.(string)
		switch key {
		case "schema_version":
			_ = dec.Decode(&snap.SchemaVersion)
		case "source":
			_ = dec.Decode(&snap.Source)
		case "generated_at":
			var s string
			_ = dec.Decode(&s)
			if t, perr := time.Parse(time.RFC3339, s); perr == nil {
				snap.GeneratedAt = t.UTC()
			}
		case "packages":
			if err := decodePackages(dec, onRecord); err != nil {
				return err
			}
		default:
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return fmt.Errorf("inventory decode %q: %w", key, err)
			}
		}
	}
	return nil
}

func decodePackages(dec *json.Decoder, onRecord func(Record) error) error {
	if _, err := dec.Token(); err != nil { // opening '['
		return fmt.Errorf("inventory packages: %w", err)
	}
	for dec.More() {
		var raw rawRecord
		if err := dec.Decode(&raw); err != nil {
			return fmt.Errorf("inventory record: %w", err)
		}
		if err := onRecord(raw.toRecord()); err != nil {
			return err
		}
	}
	if _, err := dec.Token(); err != nil { // closing ']'
		return fmt.Errorf("inventory packages: %w", err)
	}
	return nil
}

type rawRecord struct {
	Ecosystem        string   `json:"ecosystem"`
	Name             string   `json:"name"`
	PackageURL       string   `json:"package_url"`
	PURL             string   `json:"purl"`
	IDs              []string `json:"ids"`
	Source           string   `json:"source"`
	Severity         string   `json:"severity"`
	AllVersions      bool     `json:"all_versions"`
	AffectedVersions []string `json:"affected_versions"`
	Summary          string   `json:"summary"`
	References       []string `json:"references"`
	IOCs             IOCs     `json:"iocs"`
	ModifiedAt       string   `json:"modified_at"`
	PublishedAt      string   `json:"published_at"`
	ImportedAt       string   `json:"imported_at"`
}

func (r rawRecord) toRecord() Record {
	return Record{
		Ecosystem:        r.Ecosystem,
		Name:             r.Name,
		PackageURL:       r.PackageURL,
		PURL:             r.PURL,
		IDs:              r.IDs,
		Source:           r.Source,
		Severity:         r.Severity,
		AllVersions:      r.AllVersions,
		AffectedVersions: r.AffectedVersions,
		Summary:          r.Summary,
		References:       r.References,
		IOCs:             r.IOCs,
		ModifiedAt:       parseTime(r.ModifiedAt),
		PublishedAt:      parseTime(r.PublishedAt),
		ImportedAt:       parseTime(r.ImportedAt),
	}
}

func parseTime(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t.UTC()
	}
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t.UTC()
	}
	return time.Time{}
}
