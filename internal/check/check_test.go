package check

import (
	"context"
	"testing"

	"github.com/projectdiscovery/depx/internal/intel/inteltest"
	"github.com/projectdiscovery/depx/internal/osv"
	"github.com/projectdiscovery/depx/internal/ref"
)

func TestCheckMaliciousPackage(t *testing.T) {
	stub := &inteltest.Stub{
		QueryFn: func(_ context.Context, q osv.QueryRequest) (*osv.QueryResponse, error) {
			if q.Package == nil || q.Package.Name != "evil-pkg" {
				return &osv.QueryResponse{}, nil
			}
			return &osv.QueryResponse{
				Vulns: []osv.Vulnerability{{ID: "MAL-2026-TEST1"}},
			}, nil
		},
	}
	svc := NewService(stub, nil)
	result, err := svc.Check(context.Background(), ref.PackageRef{
		Ecosystem: "npm",
		Name:      "evil-pkg",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != VerdictMalicious {
		t.Fatalf("verdict = %q, want malicious", result.Verdict)
	}
	if len(result.IDs) != 1 || result.IDs[0] != "MAL-2026-TEST1" {
		t.Fatalf("ids = %v", result.IDs)
	}
}

func TestCheckCleanPackage(t *testing.T) {
	stub := &inteltest.Stub{}
	svc := NewService(stub, nil)
	result, err := svc.Check(context.Background(), ref.PackageRef{
		Ecosystem: "npm",
		Name:      "lodash",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != VerdictClean {
		t.Fatalf("verdict = %q, want clean", result.Verdict)
	}
}
