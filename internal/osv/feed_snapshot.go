package osv

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

const publishedFeedSnapshotWindow = 30 * 24 * time.Hour

type publishedFeedSnapshot struct {
	BuiltAt            time.Time         `json:"built_at"`
	CompiledModTime    time.Time         `json:"compiled_mod_time"`
	CompiledEntryCount int               `json:"compiled_entry_count"`
	Hits               []feedSnapshotHit `json:"hits"`
}

type feedSnapshotHit struct {
	Ecosystem string    `json:"ecosystem"`
	Name      string    `json:"name"`
	IDs       []string  `json:"ids"`
	Summary   string    `json:"summary,omitempty"`
	Published time.Time `json:"published"`
	Modified  time.Time `json:"modified"`
}

func PublishedFeedSnapshotPath(cacheDir string) string {
	return filepath.Join(cacheDir, "feed", "published_snapshot.json")
}

// WritePublishedFeedSnapshot stores a compact feed cache derived from the compiled
// index so feed/dashboard commands avoid parsing the full compiled.json on every run.
func WritePublishedFeedSnapshot(cacheDir, compiledPath string, idx *MaliciousIndex) error {
	if idx == nil {
		return nil
	}
	info, err := os.Stat(compiledPath)
	if err != nil {
		return err
	}
	since := time.Now().UTC().Add(-publishedFeedSnapshotWindow)
	hits := idx.ListSincePublished(since, "")
	outHits := make([]feedSnapshotHit, 0, len(hits))
	for _, h := range hits {
		outHits = append(outHits, feedSnapshotHit{
			Ecosystem: h.Ecosystem,
			Name:      h.Name,
			IDs:       append([]string(nil), h.IDs...),
			Summary:   h.Summary,
			Published: h.Published,
			Modified:  h.Modified,
		})
	}
	payload, err := json.Marshal(publishedFeedSnapshot{
		BuiltAt:            time.Now().UTC(),
		CompiledModTime:    info.ModTime().UTC(),
		CompiledEntryCount: idx.PackageCount(),
		Hits:               outHits,
	})
	if err != nil {
		return err
	}
	path := PublishedFeedSnapshotPath(cacheDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadPublishedFeedSnapshot returns recent published hits when the snapshot matches
// the on-disk compiled index.
func LoadPublishedFeedSnapshot(cacheDir, compiledPath string) ([]SearchHit, bool) {
	path := PublishedFeedSnapshotPath(cacheDir)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var snap publishedFeedSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, false
	}
	info, err := os.Stat(compiledPath)
	if err != nil {
		return nil, false
	}
	if !snap.CompiledModTime.Equal(info.ModTime().UTC()) {
		return nil, false
	}
	hits := make([]SearchHit, 0, len(snap.Hits))
	for _, h := range snap.Hits {
		hits = append(hits, SearchHit{
			Ecosystem: h.Ecosystem,
			Name:      h.Name,
			IDs:       append([]string(nil), h.IDs...),
			Summary:   h.Summary,
			Published: h.Published,
			Modified:  h.Modified,
		})
	}
	return hits, true
}

func FilterFeedHits(hits []SearchHit, since time.Time, ecosystem string) []SearchHit {
	if len(hits) == 0 {
		return nil
	}
	ecoFilter := ""
	if ecosystem != "" {
		ecoFilter = NormalizeEcosystem(ecosystem)
	}
	out := make([]SearchHit, 0, len(hits))
	for _, h := range hits {
		if h.Published.IsZero() || h.Published.Before(since) {
			continue
		}
		if ecoFilter != "" && NormalizeEcosystem(h.Ecosystem) != ecoFilter {
			continue
		}
		out = append(out, h)
	}
	sortSearchHitsByPublished(out)
	return out
}
