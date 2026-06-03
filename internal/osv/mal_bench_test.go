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
	"testing"
	"time"
)

func TestBenchmarkMALLoadApproaches(t *testing.T) {
	if os.Getenv("DEPX_MAL_BENCH") != "1" {
		t.Skip("set DEPX_MAL_BENCH=1 to run live OSV benchmarks")
	}

	ctx := context.Background()
	client := &http.Client{Timeout: 10 * time.Minute}

	entries, err := loadMALEntriesLive(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("MAL entries in index: %d", len(entries))

	osvClient := NewClient("bench", 10*time.Minute, WithCache(t.TempDir(), 0))
	osvClient.SetBypassCache(true)
	start := time.Now()
	idx, err := osvClient.buildMALIndexFromGCS(ctx, entries, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("buildMALIndexFromGCS: %d packages in %s", idx.PackageCount(), time.Since(start).Round(time.Millisecond))
}

func loadMALEntriesLive(ctx context.Context, client *http.Client) ([]IndexEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ModifiedIndexURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var entries []IndexEntry
	for _, line := range strings.Split(string(body), "\n") {
		entry, ok := parseModifiedLine(strings.TrimSpace(line))
		if !ok || !IsMaliciousID(entry.ID) {
			continue
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func malCountFromEcosystemZip(ctx context.Context, client *http.Client, ecosystem string) (int, int64, error) {
	url := fmt.Sprintf("https://storage.googleapis.com/osv-vulnerabilities/%s/all.zip", ecosystem)
	tmp, err := os.CreateTemp("", "depx-mal-bench-*.zip")
	if err != nil {
		return 0, 0, err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		tmp.Close()
		return 0, 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		tmp.Close()
		return 0, 0, err
	}
	n, err := io.Copy(tmp, resp.Body)
	resp.Body.Close()
	tmp.Close()
	if err != nil {
		return 0, 0, err
	}

	zr, err := zip.OpenReader(tmpPath)
	if err != nil {
		return 0, n, err
	}
	defer zr.Close()

	count := 0
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		base := filepath.Base(f.Name)
		if !strings.HasPrefix(base, "MAL-") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		var v Vulnerability
		if json.NewDecoder(rc).Decode(&v) == nil && v.Withdrawn == "" {
			count++
		}
		rc.Close()
	}
	return count, n, nil
}
