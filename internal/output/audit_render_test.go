package output

import (
	"testing"

	"github.com/projectdiscovery/depx/internal/audit"
)

func TestAuditTargetLabelOwners(t *testing.T) {
	t.Run("single owner", func(t *testing.T) {
		got := auditTargetLabel(&audit.Result{Paths: []string{"github.com/ehsandeep"}})
		if got != "github.com/ehsandeep" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("multiple owners", func(t *testing.T) {
		got := auditTargetLabel(&audit.Result{Paths: []string{
			"github.com/ehsandeep",
			"github.com/projectdiscovery",
		}})
		want := "github.com/ehsandeep, github.com/projectdiscovery"
		if got != want {
			t.Fatalf("got %q want %q", got, want)
		}
	})

	t.Run("truncates many owners", func(t *testing.T) {
		paths := make([]string, 10)
		for i := range paths {
			paths[i] = "github.com/org" + string(rune('a'+i))
		}
		got := auditTargetLabel(&audit.Result{Paths: paths})
		if got == "" {
			t.Fatal("expected truncated owner label")
		}
		if got[len(got)-15:] != " +2 more owners" {
			t.Fatalf("expected owner truncation suffix, got %q", got)
		}
	})
}
