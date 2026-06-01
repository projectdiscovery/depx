package github

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// APIError is returned for non-success GitHub REST responses.
type APIError struct {
	StatusCode  int
	Endpoint    string
	Body        string
	RateLimited bool
	RateLimit   rateLimitInfo
}

func newAPIError(endpoint string, status int, body []byte, h http.Header) *APIError {
	rl := parseRateLimitHeaders(h)
	return &APIError{
		StatusCode:  status,
		Endpoint:    endpoint,
		Body:        trimBody(body),
		RateLimited: isRateLimitResponse(status, rl, body),
		RateLimit:   rl,
	}
}

func (e *APIError) Error() string {
	if e.Endpoint != "" {
		return fmt.Sprintf("github request %s: status %d: %s", e.Endpoint, e.StatusCode, e.Body)
	}
	return fmt.Sprintf("github request: status %d: %s", e.StatusCode, e.Body)
}

func (e *APIError) NotFound() bool {
	return e != nil && e.StatusCode == http.StatusNotFound
}

func (e *APIError) IsRateLimited() bool {
	return e != nil && e.RateLimited
}

func AsAPIError(err error) (*APIError, bool) {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr, true
	}
	return nil, false
}

func shouldTryAsync(err error) bool {
	if err == nil {
		return false
	}
	if apiErr, ok := AsAPIError(err); ok {
		if apiErr.NotFound() || apiErr.IsRateLimited() {
			return false
		}
		if apiErr.StatusCode == http.StatusForbidden {
			return false
		}
		return apiErr.StatusCode == http.StatusAccepted ||
			apiErr.StatusCode == http.StatusBadGateway ||
			apiErr.StatusCode == http.StatusServiceUnavailable ||
			apiErr.StatusCode == http.StatusGatewayTimeout
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "status 502") ||
		strings.Contains(msg, "status 503") ||
		strings.Contains(msg, "status 504") ||
		strings.Contains(msg, "status 202")
}

func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	if apiErr, ok := AsAPIError(err); ok {
		return apiErr.NotFound()
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "status 404") || strings.Contains(msg, "not found")
}

// RepoSkipReason returns a short human-readable reason for repository resolution failure.
func RepoSkipReason(err error) string {
	if err == nil {
		return "unavailable"
	}
	if apiErr, ok := AsAPIError(err); ok {
		if apiErr.IsRateLimited() {
			if reset := formatRateLimitReset(apiErr.RateLimit); reset != "" {
				return "rate limited (resets " + reset + ")"
			}
			return "rate limited"
		}
		switch apiErr.StatusCode {
		case http.StatusNotFound:
			return "not found"
		case http.StatusForbidden:
			return "access denied"
		case http.StatusTooManyRequests:
			return "rate limited"
		default:
			return fmt.Sprintf("HTTP %d", apiErr.StatusCode)
		}
	}
	msg := err.Error()
	if idx := strings.Index(msg, "; lockfiles:"); idx > 0 {
		msg = msg[:idx]
	}
	if len(msg) > 80 {
		msg = msg[:77] + "…"
	}
	return msg
}
