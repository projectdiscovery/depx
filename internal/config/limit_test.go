package config

import "testing"

func TestNormalizeFeedLimit(t *testing.T) {
	got, err := NormalizeFeedLimit(0, DefaultLimit)
	if err != nil || got != DefaultLimit {
		t.Fatalf("zero limit: got %d err=%v", got, err)
	}
	if _, err := NormalizeFeedLimit(-1, DefaultLimit); err == nil {
		t.Fatal("expected error for negative limit")
	}
	if _, err := NormalizeFeedLimit(MaxFeedLimit+1, DefaultLimit); err == nil {
		t.Fatal("expected error for excessive limit")
	}
	got, err = NormalizeFeedLimit(MaxFeedLimit, DefaultLimit)
	if err != nil || got != MaxFeedLimit {
		t.Fatalf("max limit: got %d err=%v", got, err)
	}
}

func TestNormalizeGitHubRepoLimit(t *testing.T) {
	// No explicit limit: authenticated uses the full default, unauthenticated
	// uses the lower budget-safe default.
	got, err := NormalizeGitHubRepoLimit(0, true)
	if err != nil || got != DefaultGitHubRepoLimit {
		t.Fatalf("authenticated default: got %d err=%v", got, err)
	}
	got, err = NormalizeGitHubRepoLimit(0, false)
	if err != nil || got != DefaultGitHubRepoLimitUnauth {
		t.Fatalf("unauthenticated default: got %d err=%v", got, err)
	}

	// An explicit limit is honored regardless of auth state.
	for _, authed := range []bool{true, false} {
		got, err = NormalizeGitHubRepoLimit(25, authed)
		if err != nil || got != 25 {
			t.Fatalf("explicit limit (authed=%v): got %d err=%v", authed, got, err)
		}
	}

	if _, err := NormalizeGitHubRepoLimit(-1, false); err == nil {
		t.Fatal("expected error for negative limit")
	}
	if _, err := NormalizeGitHubRepoLimit(MaxGitHubRepoLimit+1, true); err == nil {
		t.Fatal("expected error for excessive limit")
	}
}
