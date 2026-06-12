package e2e

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type syncManifest struct {
	Source      string    `json:"source"`
	ETag        string    `json:"etag"`
	GeneratedAt time.Time `json:"generated_at"`
	Sync        struct {
		State       string    `json:"state"`
		LastSuccess time.Time `json:"last_success"`
		LastError   string    `json:"last_error"`
	} `json:"sync"`
	Compiled struct {
		PackageCount int       `json:"package_count"`
		EntryCount   int       `json:"entry_count"`
		BuiltAt      time.Time `json:"built_at"`
	} `json:"compiled"`
}

func readSyncManifest(t *testing.T, cacheDir, source string) syncManifest {
	t.Helper()
	path := filepath.Join(cacheDir, "sync", source, "manifest.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read manifest %s: %v", path, err)
	}
	var m syncManifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	return m
}

func (r *e2eRunner) runCombined(args ...string) (combined string, exit int) {
	r.t.Helper()
	return r.runCombinedWithStdin("", args...)
}

func (r *e2eRunner) runCombinedWithStdin(stdin string, args ...string) (combined string, exit int) {
	r.t.Helper()
	base := []string{"--disable-update-check", "--config", r.cfgPath}
	cmd := exec.Command(r.bin, append(base, args...)...)
	cmd.Env = append(os.Environ(), r.env...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	} else {
		cmd.Stdin = devNullStdin(r.t)
	}
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	exit = 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		} else {
			r.t.Fatalf("exec %v: %v", args, err)
		}
	}
	return outBuf.String() + errBuf.String(), exit
}

func TestE2ESyncInventory(t *testing.T) {
	srcSrv := mockSourceServer(t)
	cacheDir := t.TempDir()
	cfgPath := writeTestConfig(t, cacheDir, "")
	r := newE2ERunner(t, cfgPath, sourceEnv(srcSrv)...)

	out, code := r.run("-j", "search", "apkeep")
	if code != 0 {
		t.Fatalf("cold search exit %d: %s", code, out)
	}
	if !strings.Contains(out, "apkeep") {
		t.Fatalf("expected apkeep in search results: %s", out)
	}

	m := readSyncManifest(t, cacheDir, "inventory")
	if m.Source != "inventory" {
		t.Fatalf("manifest source = %q", m.Source)
	}
	if m.Sync.State != "idle" {
		t.Fatalf("sync state = %q, want idle", m.Sync.State)
	}
	if m.Sync.LastSuccess.IsZero() {
		t.Fatal("expected last_success after cold sync")
	}
	if m.Compiled.PackageCount == 0 {
		t.Fatal("compiled package_count is 0")
	}
	if _, err := os.Stat(filepath.Join(cacheDir, "mal", "compiled.json")); err != nil {
		t.Fatalf("missing compiled index: %v", err)
	}

	out, code = r.run("-j", "search", "evil")
	if code != 0 {
		t.Fatalf("warm search exit %d: %s", code, out)
	}
	if !strings.Contains(out, "evil-pkg") {
		t.Fatalf("expected evil-pkg on warm search: %s", out)
	}
	m2 := readSyncManifest(t, cacheDir, "inventory")
	if m2.Compiled.BuiltAt.Before(m.Compiled.BuiltAt) {
		t.Fatal("compiled index regressed on warm run")
	}
}

func TestE2ESyncDelta(t *testing.T) {
	records := &mutableRecords{records: defaultSourceRecords()}
	srcSrv := mockSourceServerWith(t, records.get)

	cacheDir := t.TempDir()
	cfgPath := writeTestConfig(t, cacheDir, "")
	r := newE2ERunner(t, cfgPath, sourceEnv(srcSrv)...)

	if _, code := r.run("-j", "search", "evil"); code != 0 {
		t.Fatalf("initial sync exit %d", code)
	}
	if out, code := r.run("-j", "search", "delta-pkg"); code != 0 || !strings.Contains(out, `"total": 0`) {
		t.Fatalf("delta-pkg should not exist yet: exit %d out %s", code, out)
	}

	// Add a new malicious package, drop the compiled cache to force a refetch.
	recent := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	records.set(append(defaultSourceRecords(), sourceRecord{
		Ecosystem: "npm", Name: "delta-pkg",
		IDs:         []string{"MAL-2026-TEST3"},
		AllVersions: true,
		Summary:     "Malicious code in delta-pkg (npm)",
		ModifiedAt:  recent, PublishedAt: recent, ImportedAt: recent,
	}))
	if err := os.Remove(filepath.Join(cacheDir, "mal", "compiled.json")); err != nil {
		t.Fatalf("remove compiled index: %v", err)
	}

	out, code := r.run("-j", "search", "delta-pkg")
	if code != 0 {
		t.Fatalf("delta search exit %d: %s", code, out)
	}
	if !strings.Contains(out, "delta-pkg") {
		t.Fatalf("expected delta-pkg after refetch: %s", out)
	}
}

// TestE2ESyncKeepsExistingOnFailure verifies depx keeps serving the last good
// index when the source is unavailable — there is no fallback source.
func TestE2ESyncKeepsExistingOnFailure(t *testing.T) {
	srcSrv := mockSourceServer(t)
	cacheDir := t.TempDir()
	cfgPath := writeTestConfig(t, cacheDir, "")

	// First, build the local index from a healthy source.
	good := newE2ERunner(t, cfgPath, sourceEnv(srcSrv)...)
	if out, code := good.run("-j", "search", "apkeep"); code != 0 || !strings.Contains(out, "apkeep") {
		t.Fatalf("warm-up sync failed: exit %d out %s", code, out)
	}

	// Now point at a dead source. The fresh local index must still answer.
	dead := newE2ERunner(t, cfgPath, "DEPX_SOURCE_URL=http://127.0.0.1:0/export")
	out, code := dead.run("-j", "search", "apkeep")
	if code != 0 {
		t.Fatalf("expected existing index to serve with dead source, exit %d: %s", code, out)
	}
	if !strings.Contains(out, "apkeep") {
		t.Fatalf("expected apkeep from cached index: %s", out)
	}
}

func TestE2ESyncUserVisibleVerbose(t *testing.T) {
	srcSrv := mockSourceServer(t)
	cacheDir := t.TempDir()
	cfgPath := writeTestConfig(t, cacheDir, "")
	r := newE2ERunner(t, cfgPath, sourceEnv(srcSrv)...)

	// Populate sync manifest before verbose status is shown (status prints in pre-run).
	if _, code := r.run("-j", "search", "apkeep"); code != 0 {
		t.Fatalf("warm-up search exit %d", code)
	}

	combined, code := r.runCombined("-v", "-n", "1")
	if code != 0 {
		t.Fatalf("verbose feed exit %d: %s", code, combined)
	}
	if !strings.Contains(combined, "index pd:") {
		t.Fatalf("expected verbose index status on stderr, got: %s", trimForLog(combined))
	}

	// The verbose status reports the public source label ("pd") and a non-zero
	// package count once the local index is built.
	combined, code = r.runCombined("-v", "audit", filepath.Join("..", "testdata", "fixtures", "clean-project"))
	if code != 0 {
		t.Fatalf("verbose audit exit %d: %s", code, combined)
	}
	if !strings.Contains(combined, "index pd:") {
		t.Fatalf("expected verbose audit index status, got: %s", trimForLog(combined))
	}
}
