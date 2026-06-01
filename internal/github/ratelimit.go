package github

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	maxRateLimitRetries = 3
	minRateLimitBackoff = 2 * time.Second
	maxRateLimitBackoff = 10 * time.Minute
)

type rateLimitInfo struct {
	Remaining  int
	ResetAt    time.Time
	RetryAfter time.Duration
}

func parseRateLimitHeaders(h http.Header) rateLimitInfo {
	if h == nil {
		return rateLimitInfo{Remaining: -1}
	}
	info := rateLimitInfo{Remaining: -1}
	if v := strings.TrimSpace(h.Get("X-Ratelimit-Remaining")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			info.Remaining = n
		}
	}
	if v := strings.TrimSpace(h.Get("X-Ratelimit-Reset")); v != "" {
		if sec, err := strconv.ParseInt(v, 10, 64); err == nil && sec > 0 {
			info.ResetAt = time.Unix(sec, 0).UTC()
		}
	}
	if v := strings.TrimSpace(h.Get("Retry-After")); v != "" {
		if sec, err := strconv.ParseInt(v, 10, 64); err == nil && sec > 0 {
			info.RetryAfter = time.Duration(sec) * time.Second
		}
	}
	return info
}

func isRateLimitResponse(status int, rl rateLimitInfo, body []byte) bool {
	if status == http.StatusTooManyRequests {
		return true
	}
	if status != http.StatusForbidden {
		return false
	}
	if rl.Remaining == 0 {
		return true
	}
	return bodyIndicatesRateLimit(body)
}

func bodyIndicatesRateLimit(body []byte) bool {
	msg := strings.ToLower(string(body))
	return strings.Contains(msg, "rate limit") ||
		strings.Contains(msg, "api rate limit exceeded") ||
		strings.Contains(msg, "secondary rate limit") ||
		strings.Contains(msg, "abuse detection")
}

func rateLimitWait(rl rateLimitInfo, attempt int) time.Duration {
	if rl.RetryAfter > 0 {
		return clampWait(rl.RetryAfter)
	}
	if !rl.ResetAt.IsZero() {
		if wait := time.Until(rl.ResetAt); wait > 0 {
			return clampWait(wait)
		}
	}
	wait := minRateLimitBackoff << attempt
	return clampWait(wait)
}

func clampWait(d time.Duration) time.Duration {
	if d < minRateLimitBackoff {
		return minRateLimitBackoff
	}
	if d > maxRateLimitBackoff {
		return maxRateLimitBackoff
	}
	return d
}

func formatRateLimitReset(rl rateLimitInfo) string {
	if rl.ResetAt.IsZero() {
		return ""
	}
	until := time.Until(rl.ResetAt)
	if until <= 0 {
		return "now"
	}
	if until < time.Minute {
		return "in less than a minute"
	}
	if until < time.Hour {
		m := int(until.Round(time.Minute) / time.Minute)
		if m == 1 {
			return "in 1 minute"
		}
		return "in " + strconv.Itoa(m) + " minutes"
	}
	h := int(until.Round(time.Minute) / time.Hour)
	if h == 1 {
		return "in 1 hour"
	}
	return "in " + strconv.Itoa(h) + " hours"
}
