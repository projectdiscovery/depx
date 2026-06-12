package cli

import "github.com/projectdiscovery/depx/internal/output"

// withSpinner runs fn while showing an indeterminate activity spinner on stderr
// for interactive sessions. The spinner self-suppresses for --json and
// non-interactive output, so callers can wrap any blocking network/API call
// unconditionally. It is always stopped (and its line cleared) before fn's
// result is returned to the caller for rendering.
func withSpinner[T any](msg string, fn func() (T, error)) (T, error) {
	sp := output.NewSpinner(outOpts(), msg)
	sp.Start()
	v, err := fn()
	sp.Stop()
	return v, err
}
