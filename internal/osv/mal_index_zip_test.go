package osv

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestParseMALZip(t *testing.T) {
	vulnJSON := []byte(`{"id":"MAL-TEST-ZIP","summary":"evil","affected":[{"package":{"name":"evil-pkg","ecosystem":"npm"}}]}`)
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)
	w, err := zw.Create("MAL-TEST-ZIP.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(vulnJSON); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	zipPath := filepath.Join(t.TempDir(), "npm.zip")
	if err := os.WriteFile(zipPath, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	idx := &MaliciousIndex{byPackage: make(map[string][]malPackageVuln)}
	var mu sync.Mutex

	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = zr.Close() }()
	for _, f := range zr.File {
		rc, _ := f.Open()
		var vuln Vulnerability
		if err := json.NewDecoder(rc).Decode(&vuln); err != nil {
			_ = rc.Close()
			t.Fatal(err)
		}
		_ = rc.Close()
		mu.Lock()
		idx.addVuln(&vuln)
		mu.Unlock()
	}

	matches := idx.Match("npm", "evil-pkg", "1.0.0")
	if len(matches) != 1 || matches[0].ID != "MAL-TEST-ZIP" {
		t.Fatalf("unexpected matches: %+v", matches)
	}
}

func TestMalEntriesByEcosystem(t *testing.T) {
	entries := []IndexEntry{
		{Ecosystem: "npm", ID: "MAL-1"},
		{Ecosystem: "PyPI", ID: "MAL-2"},
		{Ecosystem: "npm", ID: "MAL-3"},
	}
	by := malEntriesByEcosystem(entries)
	if len(by["npm"]) != 2 || len(by["PyPI"]) != 1 {
		t.Fatalf("unexpected grouping: %+v", by)
	}
}
