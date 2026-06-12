package registry

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type quarantineCacheFile struct {
	Packages map[string]bool `json:"packages"`
}

var quarantineCacheMu sync.Mutex
var quarantineChecking sync.Map // cacheDir|eco|name -> struct{}

func QuarantineCachePath(cacheDir string) string {
	return filepath.Join(cacheDir, "registry", "quarantine.json")
}

func quarantineCacheKey(ecosystem, name string) string {
	return strings.ToLower(strings.TrimSpace(ecosystem)) + "|" + strings.TrimSpace(name)
}

// HasQuarantineCacheEntry reports whether npm holding status was checked before.
func HasQuarantineCacheEntry(cacheDir, ecosystem, name string) bool {
	if cacheDir == "" || !isNPMEcosystem(ecosystem) || strings.TrimSpace(name) == "" {
		return false
	}
	cache, err := loadQuarantineCache(cacheDir)
	if err != nil {
		return false
	}
	_, ok := cache.Packages[quarantineCacheKey(ecosystem, name)]
	return ok
}

// IsQuarantinedCached reports whether npm package name is known quarantined on disk.
func IsQuarantinedCached(cacheDir, ecosystem, name string) bool {
	if cacheDir == "" || !isNPMEcosystem(ecosystem) || strings.TrimSpace(name) == "" {
		return false
	}
	cache, err := loadQuarantineCache(cacheDir)
	if err != nil {
		return false
	}
	return cache.Packages[quarantineCacheKey(ecosystem, name)]
}

// SetQuarantined persists quarantine status for an npm package.
func SetQuarantined(cacheDir, ecosystem, name string, quarantined bool) error {
	return recordQuarantineStatus(cacheDir, ecosystem, name, quarantined)
}

func recordQuarantineStatus(cacheDir, ecosystem, name string, quarantined bool) error {
	if cacheDir == "" || !isNPMEcosystem(ecosystem) || strings.TrimSpace(name) == "" {
		return nil
	}
	quarantineCacheMu.Lock()
	defer quarantineCacheMu.Unlock()

	cache, err := loadQuarantineCache(cacheDir)
	if err != nil {
		cache = quarantineCacheFile{Packages: map[string]bool{}}
	}
	if cache.Packages == nil {
		cache.Packages = map[string]bool{}
	}
	key := quarantineCacheKey(ecosystem, name)
	if v, ok := cache.Packages[key]; ok && v == quarantined {
		return nil
	}
	cache.Packages[key] = quarantined
	return saveQuarantineCache(cacheDir, cache)
}

func loadQuarantineCache(cacheDir string) (quarantineCacheFile, error) {
	path := QuarantineCachePath(cacheDir)
	data, err := os.ReadFile(path)
	if err != nil {
		return quarantineCacheFile{}, err
	}
	var cache quarantineCacheFile
	if err := json.Unmarshal(data, &cache); err != nil {
		return quarantineCacheFile{}, err
	}
	if cache.Packages == nil {
		cache.Packages = map[string]bool{}
	}
	return cache, nil
}

func saveQuarantineCache(cacheDir string, cache quarantineCacheFile) error {
	path := QuarantineCachePath(cacheDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	payload, err := json.Marshal(cache)
	if err != nil {
		return err
	}
	return os.WriteFile(path, payload, 0o644)
}

// RefreshNPMQuarantineCache checks npm holding status for names and persists results.
func RefreshNPMQuarantineCache(ctx context.Context, cacheDir, userAgent string, timeout time.Duration, names []string) {
	if cacheDir == "" || len(names) == 0 {
		return
	}
	client := NewClient(userAgent, timeout)
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" || HasQuarantineCacheEntry(cacheDir, "npm", name) {
			continue
		}
		if !beginQuarantineCheck(cacheDir, "npm", name) {
			continue
		}
		holding, err := client.IsNPMSecurityHolding(ctx, name)
		endQuarantineCheck(cacheDir, "npm", name)
		if err != nil {
			continue
		}
		_ = recordQuarantineStatus(cacheDir, "npm", name, holding)
	}
}

func beginQuarantineCheck(cacheDir, ecosystem, name string) bool {
	key := cacheDir + "|" + quarantineCacheKey(ecosystem, name)
	_, loaded := quarantineChecking.LoadOrStore(key, struct{}{})
	return !loaded
}

func endQuarantineCheck(cacheDir, ecosystem, name string) {
	key := cacheDir + "|" + quarantineCacheKey(ecosystem, name)
	quarantineChecking.Delete(key)
}
