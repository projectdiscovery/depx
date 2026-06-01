package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIsNPMSecurityHolding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/vscode-github-actions":
			_, _ = w.Write([]byte(`{"name":"vscode-github-actions","versions":{"0.0.1-security":{}}}`))
		case "/lodash":
			_, _ = w.Write([]byte(`{"name":"lodash","versions":{"4.17.21":{},"0.0.1-security":{}}}`))
		case "/http":
			_, _ = w.Write([]byte(`{"name":"http","versions":{"0.0.1-security":{}}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := NewClient("depx-test", time.Second)
	ctx := context.Background()

	orig := npmRegistryBase
	t.Cleanup(func() { npmRegistryBase = orig })
	npmRegistryBase = srv.URL

	holding, err := c.IsNPMSecurityHolding(ctx, "vscode-github-actions")
	if err != nil || !holding {
		t.Fatalf("vscode-github-actions holding=%v err=%v", holding, err)
	}
	holding, err = c.IsNPMSecurityHolding(ctx, "http")
	if err != nil || !holding {
		t.Fatalf("http holding=%v err=%v", holding, err)
	}
	holding, err = c.IsNPMSecurityHolding(ctx, "lodash")
	if err != nil || holding {
		t.Fatalf("lodash holding=%v err=%v", holding, err)
	}
	holding, err = c.IsNPMSecurityHolding(ctx, "missing-pkg")
	if err != nil || holding {
		t.Fatalf("missing holding=%v err=%v", holding, err)
	}

	// cache hit
	holding, err = c.IsNPMSecurityHolding(ctx, "http")
	if err != nil || !holding {
		t.Fatalf("cached http holding=%v err=%v", holding, err)
	}
}

func TestIsNPMSecurityVersion(t *testing.T) {
	cases := []struct {
		eco, version string
		want         bool
	}{
		{"npm", "0.0.1-security", true},
		{"npm", "0.0.0-security", true},
		{"NPM", "1.2.3-security", true},
		{"npm", "0.25.6", false},
		{"npm", "1.0.0", false},
		{"pypi", "0.0.1-security", false},
		{"go", "v0.0.1-security", false},
		{"npm", "", false},
	}
	for _, tc := range cases {
		if got := IsNPMSecurityVersion(tc.eco, tc.version); got != tc.want {
			t.Fatalf("IsNPMSecurityVersion(%q, %q) = %v, want %v", tc.eco, tc.version, got, tc.want)
		}
	}
}

func TestShouldSkipPlaceholder(t *testing.T) {
	c := NewClient("depx-test", time.Second)
	ctx := context.Background()

	ok, err := c.ShouldSkipPlaceholder(ctx, "npm", "http", "0.0.1-security")
	if err != nil || !ok {
		t.Fatalf("version stub ok=%v err=%v", ok, err)
	}
	ok, err = c.ShouldSkipPlaceholder(ctx, "npm", "lodash", "4.17.21")
	if err != nil || ok {
		t.Fatalf("normal package ok=%v err=%v", ok, err)
	}
}
