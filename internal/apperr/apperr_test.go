package apperr

import (
	"errors"
	"testing"
)

func TestUsageErrorOmitsCategorySentinel(t *testing.T) {
	err := Usage(`invalid --since value "bogus"`)
	if got := err.Error(); got != `invalid --since value "bogus"` {
		t.Fatalf("Usage().Error() = %q, want message without sentinel suffix", got)
	}
	if !errors.Is(err, ErrUsage) {
		t.Fatal("Usage error must still unwrap to ErrUsage")
	}
	if ExitCode(err) != CodeUsage {
		t.Fatalf("ExitCode = %d, want %d", ExitCode(err), CodeUsage)
	}
}

func TestUpstreamErrorKeepsWrappedDetail(t *testing.T) {
	err := Upstream("lookup failed", errors.New("advisory not found"))
	if got := err.Error(); got != "lookup failed: advisory not found" {
		t.Fatalf("Upstream().Error() = %q, want wrapped detail appended", got)
	}
}

func TestFindingsErrorOmitsSentinel(t *testing.T) {
	err := Findings("3 malicious packages found")
	if got := err.Error(); got != "3 malicious packages found" {
		t.Fatalf("Findings().Error() = %q, want message without sentinel suffix", got)
	}
}
