package registry

import (
	"context"
	"testing"
	"time"
)

func TestExistsUsesCache(t *testing.T) {
	c := NewClient("depx-test", time.Second)
	c.existsCache.Store(existsCacheKey("npm", "lodash", ""), true)

	ok, err := c.Exists(context.Background(), "npm", "lodash", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected cached true")
	}
}
