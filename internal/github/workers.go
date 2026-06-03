package github

const (
	parallelWorkersAuth   = 20
	parallelWorkersUnauth = 5
)

// ParallelWorkers returns a safe concurrency limit for GitHub API fetches.
// Unauthenticated access is capped lower to avoid exhausting the ~60 req/hr budget.
func ParallelWorkers(token string) int {
	if TokenFromEnv() != "" || token != "" {
		return parallelWorkersAuth
	}
	return parallelWorkersUnauth
}
