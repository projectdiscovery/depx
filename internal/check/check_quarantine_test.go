package check

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/projectdiscovery/depx/internal/intel/inteltest"
	"github.com/projectdiscovery/depx/internal/malindex"
	"github.com/projectdiscovery/depx/internal/ref"
	"github.com/projectdiscovery/depx/internal/registry"
)

func TestCheckQuarantinedNPMHolding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"name":"nodemon-webpatch","versions":{"0.0.1-security":{}}}`))
	}))
	defer srv.Close()

	orig := registry.NPMRegistryBaseForTest()
	t.Cleanup(func() { registry.SetNPMRegistryBaseForTest(orig) })
	registry.SetNPMRegistryBaseForTest(srv.URL)

	stub := &inteltest.Stub{
		QueryFn: func(_ context.Context, q malindex.QueryRequest) (*malindex.QueryResponse, error) {
			if q.Package != nil && q.Package.Name == "nodemon-webpatch" {
				return &malindex.QueryResponse{
					Vulns: []malindex.Vulnerability{{ID: "MAL-2026-5180"}},
				}, nil
			}
			return &malindex.QueryResponse{}, nil
		},
	}
	cacheDir := t.TempDir()
	reg := registry.NewClient("depx-test", time.Second)
	svc := NewService(stub, reg, cacheDir)

	result, err := svc.Check(context.Background(), ref.PackageRef{
		Ecosystem: "npm",
		Name:      "nodemon-webpatch",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != VerdictQuarantined {
		t.Fatalf("verdict = %q, want quarantined", result.Verdict)
	}
	if len(result.IDs) != 1 || result.IDs[0] != "MAL-2026-5180" {
		t.Fatalf("ids = %v", result.IDs)
	}
	if !registry.IsQuarantinedCached(cacheDir, "npm", "nodemon-webpatch") {
		t.Fatal("expected quarantine cache entry")
	}
}
