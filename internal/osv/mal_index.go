package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"deps.dev/util/semver"
)

// MaliciousIndex is an in-memory index of OSV MAL advisories for local matching.
type MaliciousIndex struct {
	byPackage map[string][]malPackageVuln
}

type malPackageVuln struct {
	ID         string
	Summary    string
	Published  time.Time
	Modified   time.Time
	Versions   map[string]struct{}
	Ranges     []Range
	AnyVersion bool
}

type IndexLoadProgress func(loaded, total int)
type IndexLoadStatus func(msg string)

const (
	malCompiledCacheTTL   = 7 * 24 * time.Hour
	malCompiledCountDrift = 1000
)

func (c *Client) LoadMaliciousIndex(ctx context.Context, onProgress IndexLoadProgress, onStatus IndexLoadStatus) (*MaliciousIndex, error) {
	entries, err := c.loadMALIndexEntries(ctx)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return &MaliciousIndex{byPackage: map[string][]malPackageVuln{}}, nil
	}

	if c.cacheDir != "" && !c.bypassCache {
		if idx, ok := loadCompiledMALIndex(compiledMALCachePath(c.cacheDir), len(entries)); ok {
			if onProgress != nil {
				onProgress(len(entries), len(entries))
			}
			return idx, nil
		}
	}

	idx, err := c.buildMALIndexFromGCS(ctx, entries, onProgress, onStatus)
	if err != nil {
		return nil, err
	}

	if c.cacheDir != "" && !c.bypassCache {
		_ = saveCompiledMALIndex(compiledMALCachePath(c.cacheDir), len(entries), idx)
	}
	return idx, nil
}

type compiledMALCache struct {
	BuiltAt    time.Time                    `json:"built_at"`
	EntryCount int                          `json:"entry_count"`
	Packages   map[string][]compiledMALVuln `json:"packages"`
}

type compiledMALVuln struct {
	ID         string   `json:"id"`
	Summary    string   `json:"summary"`
	Published  string   `json:"published,omitempty"`
	Modified   string   `json:"modified,omitempty"`
	Versions   []string `json:"versions,omitempty"`
	Ranges     []Range  `json:"ranges,omitempty"`
	AnyVersion bool     `json:"any_version,omitempty"`
}

func compiledMALCachePath(cacheDir string) string {
	return CompiledCachePath(cacheDir, "compiled")
}

func CompiledCachePath(cacheDir, name string) string {
	return filepath.Join(cacheDir, "mal", name+".json")
}

func LoadCompiledIndex(path string, entryCount int) (*MaliciousIndex, bool) {
	return loadCompiledMALIndex(path, entryCount)
}

func LoadCompiledIndexIfFresh(path string) (*MaliciousIndex, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var cached compiledMALCache
	if err := json.Unmarshal(data, &cached); err != nil {
		return nil, false
	}
	if malCompiledCacheTTL > 0 && time.Since(cached.BuiltAt) > malCompiledCacheTTL {
		return nil, false
	}
	return loadCompiledMALIndexFromCache(cached)
}

func loadCompiledMALIndexFromCache(cached compiledMALCache) (*MaliciousIndex, bool) {
	idx := &MaliciousIndex{byPackage: make(map[string][]malPackageVuln, len(cached.Packages))}
	for key, items := range cached.Packages {
		out := make([]malPackageVuln, 0, len(items))
		for _, item := range items {
			pv := malPackageVuln{
				ID:         item.ID,
				Summary:    item.Summary,
				Published:  parseCompiledTime(item.Published),
				Modified:   parseCompiledTime(item.Modified),
				Ranges:     item.Ranges,
				AnyVersion: item.AnyVersion,
			}
			if len(item.Versions) > 0 {
				pv.Versions = make(map[string]struct{}, len(item.Versions))
				for _, v := range item.Versions {
					pv.Versions[v] = struct{}{}
				}
			}
			out = append(out, pv)
		}
		idx.byPackage[key] = out
	}
	return idx, true
}

func SaveCompiledIndex(path string, entryCount int, idx *MaliciousIndex) error {
	return saveCompiledMALIndex(path, entryCount, idx)
}

func compiledMALCacheValid(cached compiledMALCache, entryCount int) bool {
	if malCompiledCacheTTL > 0 && time.Since(cached.BuiltAt) > malCompiledCacheTTL {
		return false
	}
	if cached.EntryCount == entryCount {
		return true
	}
	// Index grew since cache was built; a small drift is OK for local scanning.
	if entryCount > cached.EntryCount && entryCount-cached.EntryCount <= malCompiledCountDrift {
		return true
	}
	return false
}

func loadCompiledMALIndex(path string, entryCount int) (*MaliciousIndex, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var cached compiledMALCache
	if err := json.Unmarshal(data, &cached); err != nil {
		return nil, false
	}
	if !compiledMALCacheValid(cached, entryCount) {
		return nil, false
	}
	idx := &MaliciousIndex{byPackage: make(map[string][]malPackageVuln, len(cached.Packages))}
	for key, items := range cached.Packages {
		out := make([]malPackageVuln, 0, len(items))
		for _, item := range items {
			pv := malPackageVuln{
				ID:         item.ID,
				Summary:    item.Summary,
				Published:  parseCompiledTime(item.Published),
				Modified:   parseCompiledTime(item.Modified),
				Ranges:     item.Ranges,
				AnyVersion: item.AnyVersion,
			}
			if len(item.Versions) > 0 {
				pv.Versions = make(map[string]struct{}, len(item.Versions))
				for _, v := range item.Versions {
					pv.Versions[v] = struct{}{}
				}
			}
			out = append(out, pv)
		}
		idx.byPackage[key] = out
	}
	return idx, true
}

func saveCompiledMALIndex(path string, entryCount int, idx *MaliciousIndex) error {
	if idx == nil {
		return nil
	}
	out := compiledMALCache{
		BuiltAt:    time.Now().UTC(),
		EntryCount: entryCount,
		Packages:   make(map[string][]compiledMALVuln, len(idx.byPackage)),
	}
	for key, items := range idx.byPackage {
		compiled := make([]compiledMALVuln, 0, len(items))
		for _, pv := range items {
			item := compiledMALVuln{
				ID:         pv.ID,
				Summary:    pv.Summary,
				Published:  formatCompiledTime(pv.Published),
				Modified:   formatCompiledTime(pv.Modified),
				Ranges:     pv.Ranges,
				AnyVersion: pv.AnyVersion,
			}
			if len(pv.Versions) > 0 {
				item.Versions = make([]string, 0, len(pv.Versions))
				for v := range pv.Versions {
					item.Versions = append(item.Versions, v)
				}
			}
			compiled = append(compiled, item)
		}
		out.Packages[key] = compiled
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	payload, err := json.Marshal(out)
	if err != nil {
		return err
	}
	return os.WriteFile(path, payload, 0o644)
}

func (c *Client) loadMALIndexEntries(ctx context.Context) ([]IndexEntry, error) {
	cachePath := filepath.Join(c.cacheDir, "feed", "index.json")
	if c.cacheDir != "" && !c.bypassCache {
		if cached, err := readMALIndexCache(cachePath, c.cacheTTL); err == nil {
			return filterMALEntries(cached), nil
		}
	}

	index, err := StreamModifiedIndex(ctx, ModifiedIndexURLFromEnv(), c.userAgent, c.httpClient.HTTPClient.Timeout)
	if err != nil {
		if c.cacheDir != "" {
			if cached, readErr := readMALIndexCacheStale(cachePath); readErr == nil {
				return filterMALEntries(cached), nil
			}
		}
		return nil, err
	}
	if c.cacheDir != "" {
		_ = writeMALIndexCache(cachePath, index)
	}
	return filterMALEntries(index), nil
}

func filterMALEntries(entries []IndexEntry) []IndexEntry {
	out := make([]IndexEntry, 0, len(entries))
	for _, e := range entries {
		if IsMaliciousID(e.ID) {
			out = append(out, e)
		}
	}
	return out
}

type malCachedIndex struct {
	FetchedAt time.Time    `json:"fetched_at"`
	Entries   []IndexEntry `json:"entries"`
}

func readMALIndexCache(path string, ttl time.Duration) ([]IndexEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cached malCachedIndex
	if err := json.Unmarshal(data, &cached); err != nil {
		return nil, err
	}
	if ttl > 0 && time.Since(cached.FetchedAt) > ttl {
		return nil, fmt.Errorf("cache expired")
	}
	return cached.Entries, nil
}

func readMALIndexCacheStale(path string) ([]IndexEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cached malCachedIndex
	if err := json.Unmarshal(data, &cached); err != nil {
		return nil, err
	}
	return cached.Entries, nil
}

func writeMALIndexCache(path string, entries []IndexEntry) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	payload, err := json.Marshal(malCachedIndex{
		FetchedAt: time.Now().UTC(),
		Entries:   entries,
	})
	if err != nil {
		return err
	}
	return os.WriteFile(path, payload, 0o644)
}

// NewEmptyMaliciousIndex returns an empty malicious package index.
func NewEmptyMaliciousIndex() *MaliciousIndex {
	return &MaliciousIndex{byPackage: map[string][]malPackageVuln{}}
}

// AddVuln indexes a vulnerability record into the malicious package index.
func (idx *MaliciousIndex) AddVuln(vuln *Vulnerability) {
	idx.addVuln(vuln)
}

func (idx *MaliciousIndex) addVuln(vuln *Vulnerability) {
	for _, aff := range vuln.Affected {
		if aff.Package == nil || aff.Package.Name == "" {
			continue
		}
		pv := malPackageVuln{
			ID:        vuln.ID,
			Summary:   vuln.Summary,
			Published: vuln.PublishedTime(),
			Modified:  vuln.ModifiedTime(),
		}
		if len(aff.Versions) > 0 {
			pv.Versions = make(map[string]struct{}, len(aff.Versions))
			for _, v := range aff.Versions {
				pv.Versions[v] = struct{}{}
			}
		}
		if len(aff.Ranges) > 0 {
			pv.Ranges = aff.Ranges
		}
		if len(aff.Versions) == 0 && len(aff.Ranges) == 0 {
			pv.AnyVersion = true
		}
		key := packageKey(aff.Package.Ecosystem, aff.Package.Name)
		idx.byPackage[key] = append(idx.byPackage[key], pv)
	}
}

// AddListing indexes a malicious package from a summary listing (e.g. PD native API).
func (idx *MaliciousIndex) AddListing(ecosystem, name, id, summary string, allVersions bool, versions []string, published, modified time.Time) {
	if idx == nil || id == "" || name == "" {
		return
	}
	if idx.byPackage == nil {
		idx.byPackage = make(map[string][]malPackageVuln)
	}
	pv := malPackageVuln{
		ID:        id,
		Summary:   summary,
		Published: published.UTC(),
		Modified:  modified.UTC(),
	}
	if allVersions && len(versions) == 0 {
		pv.AnyVersion = true
	}
	if len(versions) > 0 {
		pv.Versions = make(map[string]struct{}, len(versions))
		for _, v := range versions {
			pv.Versions[v] = struct{}{}
		}
	}
	if len(versions) == 0 && !allVersions {
		pv.AnyVersion = true
	}
	key := packageKey(ecosystem, name)
	idx.byPackage[key] = append(idx.byPackage[key], pv)
}

func packageKey(ecosystem, name string) string {
	return normalizeEcosystem(ecosystem) + "|" + strings.ToLower(name)
}

func normalizeEcosystem(eco string) string {
	switch strings.ToLower(eco) {
	case "pypi", "python":
		return "PyPI"
	case "go", "golang":
		return "Go"
	case "crates", "cargo", "rust", "crates.io":
		return "crates.io"
	case "ruby", "gem", "rubygems":
		return "RubyGems"
	case "npm", "javascript", "js":
		return "npm"
	case "maven", "java":
		return "Maven"
	default:
		return eco
	}
}

// SearchHit is a package name match in the malicious package index.
type SearchHit struct {
	Ecosystem string
	Name      string
	IDs       []string
	Summary   string
	Published time.Time
	Modified  time.Time
}

// Search returns packages whose names contain query (case-insensitive).
func (idx *MaliciousIndex) Search(query, ecosystem string, limit int) []SearchHit {
	if idx == nil {
		return nil
	}
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return nil
	}
	if limit <= 0 {
		limit = 25
	}
	ecoFilter := ""
	if ecosystem != "" {
		ecoFilter = normalizeEcosystem(ecosystem)
	}

	hits := make([]SearchHit, 0, limit)
	for key, vulns := range idx.byPackage {
		if len(vulns) == 0 {
			continue
		}
		eco, name := splitPackageKey(key)
		if ecoFilter != "" && eco != ecoFilter {
			continue
		}
		if !strings.Contains(strings.ToLower(name), query) {
			continue
		}
		ids := make([]string, 0, len(vulns))
		summary := ""
		var published, modified time.Time
		for _, v := range vulns {
			ids = append(ids, v.ID)
			if summary == "" {
				summary = v.Summary
			}
			if published.IsZero() && !v.Published.IsZero() {
				published = v.Published
			}
			if modified.IsZero() || (!v.Modified.IsZero() && v.Modified.After(modified)) {
				modified = v.Modified
			}
		}
		hits = append(hits, SearchHit{
			Ecosystem: eco,
			Name:      name,
			IDs:       ids,
			Summary:   summary,
			Published: published,
			Modified:  modified,
		})
		if len(hits) >= limit {
			break
		}
	}
	sortSearchHits(hits)
	if len(hits) > limit {
		hits = hits[:limit]
	}
	return hits
}

func splitPackageKey(key string) (ecosystem, name string) {
	parts := strings.SplitN(key, "|", 2)
	if len(parts) != 2 {
		return "", key
	}
	return parts[0], parts[1]
}

func sortSearchHits(hits []SearchHit) {
	sort.Slice(hits, func(i, j int) bool {
		ti := hits[i].Modified
		if ti.IsZero() {
			ti = hits[i].Published
		}
		tj := hits[j].Modified
		if tj.IsZero() {
			tj = hits[j].Published
		}
		return ti.After(tj)
	})
}

// MalMatch is a local match against the malicious package database.
type MalMatch struct {
	ID        string
	Summary   string
	Published time.Time
	Modified  time.Time
}

// Match returns matching MAL advisories for a package, or nil if clean.
func (idx *MaliciousIndex) Match(ecosystem, name, version string) []MalMatch {
	if idx == nil {
		return nil
	}
	key := packageKey(ecosystem, name)
	candidates := idx.byPackage[key]
	if len(candidates) == 0 {
		return nil
	}
	out := make([]MalMatch, 0, len(candidates))
	for _, pv := range candidates {
		if pv.matches(version) {
			out = append(out, MalMatch{
				ID:        pv.ID,
				Summary:   pv.Summary,
				Published: pv.Published,
				Modified:  pv.Modified,
			})
		}
	}
	return out
}

func (idx *MaliciousIndex) PackageCount() int {
	if idx == nil {
		return 0
	}
	return len(idx.byPackage)
}

func (pv malPackageVuln) matches(version string) bool {
	if pv.AnyVersion && len(pv.Versions) == 0 && len(pv.Ranges) == 0 {
		return true
	}
	if len(pv.Versions) > 0 {
		if _, ok := pv.Versions[version]; ok {
			return true
		}
	}
	for _, r := range pv.Ranges {
		if versionInRange(version, r) {
			return true
		}
	}
	return false
}

func versionInRange(version string, r Range) bool {
	if version == "" {
		return false
	}
	switch strings.ToUpper(r.Type) {
	case "SEMVER", "ECOSYSTEM", "":
		return semverInRange(version, r.Events)
	default:
		return semverInRange(version, r.Events)
	}
}

func semverInRange(version string, events []Event) bool {
	if version == "" {
		return false
	}
	sys := semver.NPM
	introduced := "0"
	fixed := ""
	lastAffected := ""
	for _, e := range events {
		if e.Introduced != "" {
			introduced = e.Introduced
		}
		if e.Fixed != "" {
			fixed = e.Fixed
		}
		if e.LastAffected != "" {
			lastAffected = e.LastAffected
		}
	}
	if introduced != "0" {
		if cmp := sys.Compare(version, introduced); cmp < 0 {
			return false
		}
	}
	if fixed != "" {
		if cmp := sys.Compare(version, fixed); cmp >= 0 {
			return false
		}
	}
	if lastAffected != "" {
		if cmp := sys.Compare(version, lastAffected); cmp > 0 {
			return false
		}
	}
	return true
}

func parseCompiledTime(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t.UTC()
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t.UTC()
	}
	return time.Time{}
}

func formatCompiledTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}
