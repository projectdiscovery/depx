package github

import "testing"

func TestParallelWorkers(t *testing.T) {
	t.Setenv("DEPX_GITHUB_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	if got := ParallelWorkers(""); got != parallelWorkersUnauth {
		t.Fatalf("unauth workers = %d, want %d", got, parallelWorkersUnauth)
	}
	if got := ParallelWorkers("token"); got != parallelWorkersAuth {
		t.Fatalf("auth workers = %d, want %d", got, parallelWorkersAuth)
	}

	t.Setenv("GITHUB_TOKEN", "env-token")
	if got := ParallelWorkers(""); got != parallelWorkersAuth {
		t.Fatalf("env token workers = %d, want %d", got, parallelWorkersAuth)
	}
}
