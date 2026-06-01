package pd

import (
	"testing"
)

func TestEnabled(t *testing.T) {
	t.Setenv("DEPX_INTEL_SOURCE", "")
	t.Setenv("DEPX_PD_API", "")
	t.Setenv("DEPX_PD_API_TOKEN", "")
	t.Setenv("DEPX_PD_TOKEN", "")

	if Enabled() {
		t.Fatal("expected disabled without token")
	}

	t.Setenv("DEPX_PD_API", "1")
	if Enabled() {
		t.Fatal("expected disabled with flag but no token")
	}

	t.Setenv("DEPX_PD_API_TOKEN", "secret")
	if !Enabled() {
		t.Fatal("expected enabled with DEPX_PD_API=1 and token")
	}

	t.Setenv("DEPX_PD_API", "")
	t.Setenv("DEPX_INTEL_SOURCE", "pd")
	if !Enabled() {
		t.Fatal("expected enabled with DEPX_INTEL_SOURCE=pd and token")
	}

	t.Setenv("DEPX_INTEL_SOURCE", "osv")
	if Enabled() {
		t.Fatal("expected disabled when DEPX_INTEL_SOURCE=osv")
	}
}

func TestAPIURL(t *testing.T) {
	t.Setenv("DEPX_PD_API_URL", "")
	if APIURL() != DefaultAPIURL {
		t.Fatalf("default url = %q", APIURL())
	}
	t.Setenv("DEPX_PD_API_URL", "https://example.test/")
	if APIURL() != "https://example.test" {
		t.Fatalf("trimmed url = %q", APIURL())
	}
}

func TestToken(t *testing.T) {
	t.Setenv("DEPX_PD_API_TOKEN", "")
	t.Setenv("DEPX_PD_TOKEN", "")
	if Token() != "" {
		t.Fatal("expected empty token")
	}
	t.Setenv("DEPX_PD_TOKEN", "fallback")
	if Token() != "fallback" {
		t.Fatalf("token = %q", Token())
	}
	t.Setenv("DEPX_PD_API_TOKEN", "primary")
	if Token() != "primary" {
		t.Fatalf("token = %q", Token())
	}
}

func TestOSVBaseURL(t *testing.T) {
	t.Setenv("DEPX_PD_API_URL", "https://api.test")
	if OSVBaseURL() != "https://api.test/v1" {
		t.Fatalf("osv base = %q", OSVBaseURL())
	}
}
