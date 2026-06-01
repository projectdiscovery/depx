package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseRateLimitHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("X-Ratelimit-Remaining", "0")
	h.Set("X-Ratelimit-Reset", "1700000000")
	h.Set("Retry-After", "30")

	rl := parseRateLimitHeaders(h)
	if rl.Remaining != 0 {
		t.Fatalf("remaining=%d", rl.Remaining)
	}
	if rl.ResetAt.Unix() != 1700000000 {
		t.Fatalf("reset=%v", rl.ResetAt)
	}
	if rl.RetryAfter != 30*time.Second {
		t.Fatalf("retry-after=%v", rl.RetryAfter)
	}
}

func TestIsRateLimitResponse(t *testing.T) {
	if !isRateLimitResponse(http.StatusTooManyRequests, rateLimitInfo{}, nil) {
		t.Fatal("expected 429 to be rate limited")
	}
	rl := rateLimitInfo{Remaining: 0}
	if !isRateLimitResponse(http.StatusForbidden, rl, []byte(`{"message":"API rate limit exceeded"}`)) {
		t.Fatal("expected 403 with remaining=0 to be rate limited")
	}
	if isRateLimitResponse(http.StatusForbidden, rateLimitInfo{Remaining: 1}, []byte(`{"message":"Resource not accessible by integration"}`)) {
		t.Fatal("expected permission 403 not to be rate limited")
	}
}

func TestDoRequestRetriesOn429(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls < 3 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	client := NewClient("depx-test", "token", time.Second)
	client.APIBase = srv.URL
	client.PollEvery = time.Millisecond

	body, status, err := client.doRequest(context.Background(), http.MethodGet, srv.URL+"/test", nil)
	if err != nil {
		t.Fatalf("doRequest: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("status=%d", status)
	}
	if calls != 3 {
		t.Fatalf("calls=%d want 3", calls)
	}
	if len(body) == 0 {
		t.Fatal("expected body")
	}
}

func TestRepoSkipReasonRateLimitVsForbidden(t *testing.T) {
	reset := time.Now().Add(30 * time.Minute).Unix()
	h := http.Header{}
	h.Set("X-Ratelimit-Remaining", "0")
	h.Set("X-Ratelimit-Reset", strconv.FormatInt(reset, 10))

	rateErr := newAPIError("https://api.github.com/x", http.StatusForbidden, []byte(`{"message":"API rate limit exceeded"}`), h)
	if got := RepoSkipReason(rateErr); got == "access denied" || !strings.Contains(got, "rate limited") {
		t.Fatalf("expected rate limit reason, got %q", got)
	}

	permErr := newAPIError("https://api.github.com/x", http.StatusForbidden, []byte(`{"message":"Resource not accessible by integration"}`), http.Header{"X-Ratelimit-Remaining": []string{"4999"}})
	if got := RepoSkipReason(permErr); got != "access denied" {
		t.Fatalf("expected access denied, got %q", got)
	}
}
