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
