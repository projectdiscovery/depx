package github

import (
	"os"
	"testing"
)

func TestTokenFromEnv(t *testing.T) {
	t.Setenv("DEPX_GITHUB_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	t.Setenv("DEPX_GITHUB_TOKEN", "depx-token")
	if got := TokenFromEnv(); got != "depx-token" {
		t.Fatalf("DEPX_GITHUB_TOKEN = %q", got)
	}

	t.Setenv("DEPX_GITHUB_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "github-token")
	if got := TokenFromEnv(); got != "github-token" {
		t.Fatalf("GITHUB_TOKEN = %q", got)
	}

	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "gh-token")
	if got := TokenFromEnv(); got != "gh-token" {
		t.Fatalf("GH_TOKEN = %q", got)
	}

	_ = os.Unsetenv("GH_TOKEN")
}
