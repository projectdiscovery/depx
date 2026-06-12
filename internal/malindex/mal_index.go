package malindex

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"deps.dev/util/semver"

	"github.com/projectdiscovery/depx/internal/inventory"
)

// MaliciousIndex is an in-memory index of malicious-package advisories for
// local matching, lookup, and feed/search rendering.
type MaliciousIndex struct {
	byPackage map[string][]malPackageVuln
	// byID maps every advisory ID (primary or alias) to its package key for
	// O(1) lookups. It is rebuilt whenever the index is (re)loaded.
	byID map[string]string
}

type malPackageVuln struct {
	ID         string
	Summary    string
	Severity   string
	Source     string
	Published  time.Time
	Modified   time.Time
	Imported   time.Time
	Aliases    []string
	References []string
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

type compiledMALCache struct {
	BuiltAt    time.Time                    `json:"built_at"`
	EntryCount int                          `json:"entry_count"`
	Packages   map[string][]compiledMALVuln `json:"packages"`
}

type compiledMALVuln struct {
	ID         string   `json:"id"`
	Summary    string   `json:"summary"`
	Severity   string   `json:"severity,omitempty"`
	Source     string   `json:"source,omitempty"`
	Published  string   `json:"published,omitempty"`
	Modified   string   `json:"modified,omitempty"`
	Imported   string   `json:"imported,omitempty"`
	Aliases    []string `json:"aliases,omitempty"`
	References []string `json:"references,omitempty"`
	Versions   []string `json:"versions,omitempty"`
	Ranges     []Range  `json:"ranges,omitempty"`
	AnyVersion bool     `json:"any_version,omitempty"`
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

// LoadCompiledIndexStale returns the on-disk compiled index even when its TTL
// has expired. Feed rendering prefers this over scanning the modified index.
func LoadCompiledIndexStale(path string) (*MaliciousIndex, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var cached compiledMALCache
	if err := json.Unmarshal(data, &cached); err != nil {
		return nil, false
	}
	return loadCompiledMALIndexFromCache(cached)
}

func loadCompiledMALIndexFromCache(cached compiledMALCache) (*MaliciousIndex, bool) {
	idx := &MaliciousIndex{byPackage: make(map[string][]malPackageVuln, len(cached.Packages))}
	for key, items := range cached.Packages {
		out := make([]malPackageVuln, 0, len(items))
		for _, item := range items {
			out = append(out, item.toPackageVuln())
		}
		idx.byPackage[key] = out
	}
	idx.rebuildByID()
	return idx, true
}

func (item compiledMALVuln) toPackageVuln() malPackageVuln {
	pv := malPackageVuln{
		ID:         item.ID,
		Summary:    item.Summary,
		Severity:   item.Severity,
		Source:     item.Source,
		Published:  parseCompiledTime(item.Published),
		Modified:   parseCompiledTime(item.Modified),
		Imported:   parseCompiledTime(item.Imported),
		Aliases:    item.Aliases,
		References: item.References,
		Ranges:     item.Ranges,
		AnyVersion: item.AnyVersion,
	}
	if len(item.Versions) > 0 {
		pv.Versions = make(map[string]struct{}, len(item.Versions))
		for _, v := range item.Versions {
			pv.Versions[v] = struct{}{}
		}
	}
	return pv
}

func SaveCompiledIndex(path string, entryCount int, idx *MaliciousIndex) error {
	if err := saveCompiledMALIndex(path, entryCount, idx); err != nil {
		return err
	}
	cacheDir := filepath.Dir(filepath.Dir(path))
	_ = WritePublishedFeedSnapshot(cacheDir, path, idx)
	return nil
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
			out = append(out, item.toPackageVuln())
		}
		idx.byPackage[key] = out
	}
	idx.rebuildByID()
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
				Severity:   pv.Severity,
				Source:     pv.Source,
				Published:  formatCompiledTime(pv.Published),
				Modified:   formatCompiledTime(pv.Modified),
				Imported:   formatCompiledTime(pv.Imported),
				Aliases:    pv.Aliases,
				References: pv.References,
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
			Aliases:   append([]string(nil), vuln.Aliases...),
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
		idx.registerID(key, pv)
	}
}

// AddRecord indexes a malicious package from an inventory export record. The
// record's primary ID anchors the entry; remaining IDs are stored as aliases
// and indexed for lookup. Version coverage comes from affected_versions /
// all_versions. A record that sets neither (all_versions=false with an empty
// affected_versions list) carries no usable version coverage and is indexed
// without matching any pinned version, so name/ID lookups still surface it but
// version-pinned checks do not raise false positives.
func (idx *MaliciousIndex) AddRecord(rec inventory.Record) {
	if idx == nil || rec.Name == "" {
		return
	}
	id := rec.PrimaryID()
	if id == "" {
		return
	}
	if idx.byPackage == nil {
		idx.byPackage = make(map[string][]malPackageVuln)
	}
	pv := malPackageVuln{
		ID:         id,
		Summary:    rec.Summary,
		Severity:   rec.Severity,
		Source:     rec.Source,
		Published:  rec.PublishedAt,
		Modified:   rec.ModifiedAt,
		Imported:   rec.ImportedAt,
		Aliases:    append([]string(nil), rec.IDs[1:]...),
		References: append([]string(nil), rec.References...),
	}
	switch {
	case len(rec.AffectedVersions) > 0:
		pv.Versions = make(map[string]struct{}, len(rec.AffectedVersions))
		for _, v := range rec.AffectedVersions {
			pv.Versions[v] = struct{}{}
		}
	case rec.AllVersions:
		// The export explicitly marks every version of the package malicious.
		pv.AnyVersion = true
	default:
		// all_versions=false with no affected_versions: the export carries no
		// usable version coverage. Upstream OSV "ranges" are not exported, so a
		// ranged advisory (e.g. fsevents MAL-2023-462 affects only [1.0.0,1.2.11))
		// arrives here with an empty list. Leaving the version set empty keeps the
		// advisory discoverable by name/ID lookup without flagging unaffected
		// pinned versions as malicious.
	}
	key := packageKey(rec.Ecosystem, rec.Name)
	idx.byPackage[key] = append(idx.byPackage[key], pv)
	idx.registerID(key, pv)
}

// rebuildByID reconstructs the ID→package-key map from byPackage.
func (idx *MaliciousIndex) rebuildByID() {
	if idx == nil {
		return
	}
	idx.byID = make(map[string]string, len(idx.byPackage))
	for key, vulns := range idx.byPackage {
		for _, pv := range vulns {
			idx.registerID(key, pv)
		}
	}
}

func (idx *MaliciousIndex) registerID(key string, pv malPackageVuln) {
	if idx.byID == nil {
		idx.byID = make(map[string]string)
	}
	// Index both the canonical and lower-cased form so lookups are
	// case-insensitive (e.g. "mal-2026-5682" resolves "MAL-2026-5682").
	register := func(id string) {
		if id == "" {
			return
		}
		idx.byID[id] = key
		if lower := strings.ToLower(id); lower != id {
			idx.byID[lower] = key
		}
	}
	register(pv.ID)
	for _, alias := range pv.Aliases {
		register(alias)
	}
}

func packageKey(ecosystem, name string) string {
	return NormalizeEcosystem(ecosystem) + "|" + strings.ToLower(name)
}

// NormalizeEcosystem maps CLI/config aliases to canonical OSV ecosystem names.
func NormalizeEcosystem(eco string) string {
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
	Aliases   []string
	Summary   string
	Severity  string
	Source    string
	Published time.Time
	Modified  time.Time
	Imported  time.Time
}

// SearchMatchResult holds capped search hits and the full match count.
type SearchMatchResult struct {
	Hits  []SearchHit
	Total int
}

// Search returns packages whose names contain query (case-insensitive).
// Hits are sorted by modified/published (newest first) and capped at limit.
// Total is the number of matches before the cap.
func (idx *MaliciousIndex) Search(query, ecosystem string, limit int) SearchMatchResult {
	if idx == nil {
		return SearchMatchResult{}
	}
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return SearchMatchResult{}
	}
	if limit <= 0 {
		limit = 25
	}
	ecoFilter := ""
	if ecosystem != "" {
		ecoFilter = NormalizeEcosystem(ecosystem)
	}

	hits := make([]SearchHit, 0)
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
		severity := ""
		src := ""
		var aliases []string
		var published, modified, imported time.Time
		for _, v := range vulns {
			ids = append(ids, v.ID)
			if summary == "" {
				summary = v.Summary
			}
			if severity == "" {
				severity = v.Severity
			}
			if src == "" {
				src = v.Source
			}
			if len(aliases) == 0 {
				aliases = v.Aliases
			}
			if imported.IsZero() && !v.Imported.IsZero() {
				imported = v.Imported
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
			Aliases:   aliases,
			Summary:   summary,
			Severity:  severity,
			Source:    src,
			Published: published,
			Modified:  modified,
			Imported:  imported,
		})
	}
	total := len(hits)
	sortSearchHits(hits)
	if len(hits) > limit {
		hits = hits[:limit]
	}
	return SearchMatchResult{Hits: hits, Total: total}
}

// LookupByID returns package metadata for a malicious advisory ID (primary or
// alias) in the compiled index.
func (idx *MaliciousIndex) LookupByID(id string) (SearchHit, bool) {
	if pv, key, ok := idx.lookup(id); ok {
		eco, name := splitPackageKey(key)
		return SearchHit{
			Ecosystem: eco,
			Name:      name,
			IDs:       []string{pv.ID},
			Summary:   pv.Summary,
			Published: pv.Published,
			Modified:  pv.Modified,
		}, true
	}
	return SearchHit{}, false
}

// lookup resolves an advisory ID (primary or alias) to its indexed record.
func (idx *MaliciousIndex) lookup(id string) (malPackageVuln, string, bool) {
	if idx == nil || id == "" {
		return malPackageVuln{}, "", false
	}
	if idx.byID != nil {
		key, ok := idx.byID[id]
		if !ok {
			key, ok = idx.byID[strings.ToLower(id)]
		}
		if ok {
			for _, pv := range idx.byPackage[key] {
				if strings.EqualFold(pv.ID, id) || containsFold(pv.Aliases, id) {
					return pv, key, true
				}
			}
		}
		return malPackageVuln{}, "", false
	}
	for key, vulns := range idx.byPackage {
		for _, pv := range vulns {
			if strings.EqualFold(pv.ID, id) || containsFold(pv.Aliases, id) {
				return pv, key, true
			}
		}
	}
	return malPackageVuln{}, "", false
}

// canonicalAdvisoryID returns the stored (correctly-cased) advisory ID that a
// case-insensitive query matched, so output never echoes the user's casing.
func canonicalAdvisoryID(pv malPackageVuln, queried string) string {
	if strings.EqualFold(pv.ID, queried) {
		return pv.ID
	}
	for _, alias := range pv.Aliases {
		if strings.EqualFold(alias, queried) {
			return alias
		}
	}
	return queried
}

// Vuln synthesizes a Vulnerability record for an advisory ID from the local
// index. It returns false when the ID is not malicious or not indexed.
func (idx *MaliciousIndex) Vuln(id string) (*Vulnerability, bool) {
	pv, key, ok := idx.lookup(id)
	if !ok {
		return nil, false
	}
	eco, name := splitPackageKey(key)
	return pv.toVulnerability(canonicalAdvisoryID(pv, id), eco, name), true
}

// QueryLocal returns synthesized Vulnerability records matching a package
// (and optional version) from the local index.
func (idx *MaliciousIndex) QueryLocal(ecosystem, name, version string) []*Vulnerability {
	if idx == nil {
		return nil
	}
	key := packageKey(ecosystem, name)
	candidates := idx.byPackage[key]
	if len(candidates) == 0 {
		return nil
	}
	eco, pkgName := splitPackageKey(key)
	out := make([]*Vulnerability, 0, len(candidates))
	for _, pv := range candidates {
		if version != "" && !pv.matches(version) {
			continue
		}
		out = append(out, pv.toVulnerability(pv.ID, eco, pkgName))
	}
	return out
}

func (pv malPackageVuln) toVulnerability(id, ecosystem, name string) *Vulnerability {
	versions := make([]string, 0, len(pv.Versions))
	for v := range pv.Versions {
		versions = append(versions, v)
	}
	sort.Strings(versions)

	refs := make([]Reference, 0, len(pv.References))
	for _, u := range pv.References {
		if u == "" {
			continue
		}
		refs = append(refs, Reference{Type: "WEB", URL: u})
	}

	v := &Vulnerability{
		ID:         id,
		Summary:    pv.Summary,
		Modified:   formatCompiledTime(pv.Modified),
		Published:  formatCompiledTime(pv.Published),
		Aliases:    aliasesExcluding(pv, id),
		References: refs,
		Affected: []Affected{{
			Package:  &Package{Name: name, Ecosystem: ecosystem},
			Versions: versions,
		}},
	}
	if pv.Source != "" {
		v.DatabaseSpecific.MaliciousPackagesOrigins = []MaliciousOrigin{{
			Source:     pv.Source,
			ImportTime: formatCompiledTime(pv.Imported),
		}}
	}
	return v
}

// aliasesExcluding returns the record's full ID set (primary + aliases) minus
// the requested ID, so the synthesized record lists sibling identifiers.
func aliasesExcluding(pv malPackageVuln, id string) []string {
	out := make([]string, 0, len(pv.Aliases)+1)
	if pv.ID != "" && pv.ID != id {
		out = append(out, pv.ID)
	}
	for _, a := range pv.Aliases {
		if a != "" && a != id {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func containsFold(list []string, want string) bool {
	for _, s := range list {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

// ListSincePublished returns advisories with published >= since, newest published first.
func (idx *MaliciousIndex) ListSincePublished(since time.Time, ecosystem string) []SearchHit {
	if idx == nil {
		return nil
	}
	ecoFilter := ""
	if ecosystem != "" {
		ecoFilter = NormalizeEcosystem(ecosystem)
	}
	hits := make([]SearchHit, 0)
	for key, vulns := range idx.byPackage {
		eco, name := splitPackageKey(key)
		if ecoFilter != "" && eco != ecoFilter {
			continue
		}
		for _, item := range vulns {
			if item.Published.IsZero() || item.Published.Before(since) {
				continue
			}
			hits = append(hits, SearchHit{
				Ecosystem: eco,
				Name:      name,
				IDs:       []string{item.ID},
				Aliases:   item.Aliases,
				Summary:   item.Summary,
				Severity:  item.Severity,
				Source:    item.Source,
				Published: item.Published,
				Modified:  item.Modified,
				Imported:  item.Imported,
			})
		}
	}
	sortSearchHitsByPublished(hits)
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

func sortSearchHitsByPublished(hits []SearchHit) {
	sort.Slice(hits, func(i, j int) bool {
		return hits[i].Published.After(hits[j].Published)
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
