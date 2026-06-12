package audit

import (
	"os"
	"testing"
)

func TestHasGitHubInputRejectsHomePath(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip(err)
	}
	if hasGitHubInput([]string{home}) {
		t.Fatalf("home path %q must not be treated as github input", home)
	}
	if hasGitHubInput(defaultAuditPaths()) {
		t.Fatalf("default audit paths must not be treated as github input")
	}
	if !hasGitHubInput([]string{"github:projectdiscovery/depx"}) {
		t.Fatal("expected explicit github ref to be detected")
	}
	if hasGitHubInput([]string{"projectdiscovery/depx"}) {
		t.Fatal("bare owner/repo must not be treated as github input for audit")
	}
}
