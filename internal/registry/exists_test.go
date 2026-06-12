package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRegistryGETExists(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/found":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := NewClient("depx-test", time.Second)
	ok, err := c.registryGETExists(context.Background(), srv.URL+"/found")
	if err != nil || !ok {
		t.Fatalf("expected found, ok=%v err=%v", ok, err)
	}
	ok, err = c.registryGETExists(context.Background(), srv.URL+"/missing")
	if err != nil || ok {
		t.Fatalf("expected missing, ok=%v err=%v", ok, err)
	}
}
