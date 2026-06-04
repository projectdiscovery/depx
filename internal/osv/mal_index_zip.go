package osv

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	gcsVulnBaseURL  = "https://storage.googleapis.com/osv-vulnerabilities"
	ZipMALThreshold = 100
	zipMALThreshold = ZipMALThreshold
)

func gcsEcosystemZipURL(ecosystem string) string {
	return gcsVulnBaseURL + "/" + ecosystem + "/all.zip"
}

func gcsVulnJSONURL(ecosystem, id string) string {
	return GCSVulnJSONURL(ecosystem, id)
}

// GCSVulnJSONURL returns the OSV GCS URL for a vulnerability record.
func GCSVulnJSONURL(ecosystem, id string) string {
	base := gcsVulnBaseURL
	if v := os.Getenv("DEPX_GCS_VULN_URL"); v != "" {
		base = strings.TrimRight(v, "/")
	}
	return base + "/" + ecosystem + "/" + id + ".json"
}

func ecosystemZipCachePath(cacheDir, ecosystem string) string {
	safe := strings.ReplaceAll(ecosystem, "/", "_")
	return filepath.Join(cacheDir, "mal", "zips", safe+".zip")
}

func malEntriesByEcosystem(entries []IndexEntry) map[string][]IndexEntry {
	out := make(map[string][]IndexEntry)
	for _, e := range entries {
		out[e.Ecosystem] = append(out[e.Ecosystem], e)
	}
	return out
}

func (c *Client) buildMALIndexFromGCS(ctx context.Context, entries []IndexEntry, onProgress IndexLoadProgress, onStatus IndexLoadStatus) (*MaliciousIndex, error) {
	byEco := malEntriesByEcosystem(entries)
	total := len(entries)
	var loaded atomic.Int32
	idx := &MaliciousIndex{byPackage: make(map[string][]malPackageVuln)}
	var mu sync.Mutex

	report := func() {
		if onProgress != nil {
			onProgress(int(loaded.Load()), total)
		}
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)

	for eco, ecoEntries := range byEco {
		if len(ecoEntries) >= zipMALThreshold {
			wg.Add(1)
			go func(ecosystem string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				n, err := c.loadMALFromEcosystemZip(ctx, ecosystem, idx, &mu, func() {
					loaded.Add(1)
					report()
				}, onStatus)
				if err != nil {
					// fall back to per-record fetch for this ecosystem
					c.loadMALEntriesGCS(ctx, ecoEntries, idx, &mu, &loaded, report)
					return
				}
				// zip path increments loaded per file; ensure count matches if zip skipped some
				_ = n
			}(eco)
			continue
		}

		wg.Add(1)
		go func(list []IndexEntry) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			c.loadMALEntriesGCS(ctx, list, idx, &mu, &loaded, report)
		}(ecoEntries)
	}

	wg.Wait()
	report()
	return idx, nil
}

func (c *Client) loadMALEntriesGCS(
	ctx context.Context,
	entries []IndexEntry,
	idx *MaliciousIndex,
	mu *sync.Mutex,
	loaded *atomic.Int32,
	report func(),
) {
	sem := make(chan struct{}, 20)
	var wg sync.WaitGroup
	for _, entry := range entries {
		wg.Add(1)
		go func(e IndexEntry) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			vuln, err := c.getVulnGCS(ctx, e.Ecosystem, e.ID)
			if err != nil || vuln == nil || vuln.Withdrawn != "" {
				return
			}
			mu.Lock()
			idx.addVuln(vuln)
			mu.Unlock()
			loaded.Add(1)
			report()
		}(entry)
	}
	wg.Wait()
}

func (c *Client) getVulnGCS(ctx context.Context, ecosystem, id string) (*Vulnerability, error) {
	if vuln, ok := c.getCachedVuln(id); ok {
		return vuln, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, gcsVulnJSONURL(ecosystem, id), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.httpClient.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gcs vuln %s: status %d", id, resp.StatusCode)
	}

	var vuln Vulnerability
	if err := json.NewDecoder(resp.Body).Decode(&vuln); err != nil {
		return nil, err
	}
	c.writeCachedVuln(id, &vuln)
	return &vuln, nil
}

func (c *Client) loadMALFromEcosystemZip(
	ctx context.Context,
	ecosystem string,
	idx *MaliciousIndex,
	mu *sync.Mutex,
	onRecord func(),
	onStatus IndexLoadStatus,
) (int, error) {
	zipPath, cleanup, err := c.ensureEcosystemZip(ctx, ecosystem, onStatus)
	if err != nil {
		return 0, err
	}
	if cleanup != nil {
		defer cleanup()
	}

	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return 0, err
	}
	defer func() { _ = zr.Close() }()

	count := 0
	for _, f := range zr.File {
		base := filepath.Base(f.Name)
		if !strings.HasPrefix(base, "MAL-") || !strings.HasSuffix(base, ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		var vuln Vulnerability
		if err := json.NewDecoder(rc).Decode(&vuln); err != nil {
			_ = rc.Close()
			continue
		}
		_ = rc.Close()
		if vuln.Withdrawn != "" {
			continue
		}
		mu.Lock()
		idx.addVuln(&vuln)
		mu.Unlock()
		c.writeCachedVuln(vuln.ID, &vuln)
		count++
		if onRecord != nil {
			onRecord()
		}
	}
	return count, nil
}

func (c *Client) ensureEcosystemZip(ctx context.Context, ecosystem string, onStatus IndexLoadStatus) (string, func(), error) {
	if c.cacheDir != "" && !c.bypassCache {
		path := ecosystemZipCachePath(c.cacheDir, ecosystem)
		if info, err := os.Stat(path); err == nil && info.Size() > 0 {
			return path, nil, nil
		}
	}

	if onStatus != nil {
		onStatus(fmt.Sprintf("Downloading %s malicious package data...", ecosystem))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, gcsEcosystemZipURL(ecosystem), nil)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)

	zipClient := &http.Client{Timeout: 10 * time.Minute}
	resp, err := zipClient.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("gcs zip %s: status %d", ecosystem, resp.StatusCode)
	}

	totalBytes := resp.ContentLength
	var lastReport int64
	reportDownload := func(written int64) {
		if onStatus == nil {
			return
		}
		if written-lastReport < 5*1024*1024 && written != totalBytes && (totalBytes <= 0 || written < totalBytes) {
			return
		}
		lastReport = written
		if totalBytes > 0 {
			onStatus(fmt.Sprintf("Downloading %s malicious package data... %s / %s",
				ecosystem, formatBytes(written), formatBytes(totalBytes)))
			return
		}
		onStatus(fmt.Sprintf("Downloading %s malicious package data... %s", ecosystem, formatBytes(written)))
	}

	if c.cacheDir != "" && !c.bypassCache {
		path := ecosystemZipCachePath(c.cacheDir, ecosystem)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return "", nil, err
		}
		tmpPath := path + ".part"
		dest, err := os.Create(tmpPath)
		if err != nil {
			return "", nil, err
		}
		counter := &countWriter{w: dest, onWrite: reportDownload}
		if _, err := io.Copy(counter, resp.Body); err != nil {
			_ = dest.Close()
			_ = os.Remove(tmpPath)
			return "", nil, err
		}
		if err := dest.Close(); err != nil {
			_ = os.Remove(tmpPath)
			return "", nil, err
		}
		if err := os.Rename(tmpPath, path); err != nil {
			_ = os.Remove(tmpPath)
			return "", nil, err
		}
		return path, nil, nil
	}

	tmp, err := os.CreateTemp("", "depx-mal-*.zip")
	if err != nil {
		return "", nil, err
	}
	path := tmp.Name()
	counter := &countWriter{w: tmp, onWrite: reportDownload}
	if _, err := io.Copy(counter, resp.Body); err != nil {
		_ = tmp.Close()
		_ = os.Remove(path)
		return "", nil, err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(path)
		return "", nil, err
	}
	return path, func() { _ = os.Remove(path) }, nil
}

type countWriter struct {
	w       io.Writer
	written int64
	onWrite func(int64)
}

func (cw *countWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	if n > 0 {
		cw.written += int64(n)
		if cw.onWrite != nil {
			cw.onWrite(cw.written)
		}
	}
	return n, err
}

func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}
