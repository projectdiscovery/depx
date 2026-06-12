package malindex

import (
	"testing"
	"time"
)

func TestCompiledMALCacheValid(t *testing.T) {
	now := time.Now().UTC()
	fresh := compiledMALCache{BuiltAt: now, EntryCount: 226705}

	if !compiledMALCacheValid(fresh, 226705) {
		t.Fatal("exact count should be valid")
	}
	if !compiledMALCacheValid(fresh, 226706) {
		t.Fatal("small drift should be valid")
	}
	if !compiledMALCacheValid(fresh, 227705) {
		t.Fatal("drift within limit should be valid")
	}
	if compiledMALCacheValid(fresh, 227706) {
		t.Fatal("large drift should be invalid")
	}
	if compiledMALCacheValid(fresh, 226000) {
		t.Fatal("shrunk index should be invalid")
	}

	stale := compiledMALCache{BuiltAt: now.Add(-8 * 24 * time.Hour), EntryCount: 226705}
	if compiledMALCacheValid(stale, 226705) {
		t.Fatal("expired cache should be invalid")
	}
}
