package osv

import (
	"context"
	"io"
	"net/http"
	"os"
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
	defer func() { _ = resp.Body.Close() }()
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
