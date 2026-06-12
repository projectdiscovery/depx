package sync

import (
	"context"
	"sync"
	"time"

	"github.com/projectdiscovery/depx/internal/malindex"
)

// defaultMinInterval matches the upstream inventory refresh cadence: the export
// is regenerated hourly, so depx refreshes its local copy no more than once an
// hour.
const defaultMinInterval = time.Hour

type Config struct {
	CacheDir    string
	UserAgent   string
	Timeout     time.Duration
	SourceURL   string
	MinInterval time.Duration

	scheduleBackground func(fn func(context.Context))
}

type Engine struct {
	cfg Config

	mu      sync.Mutex
	running bool
	status  Status

	wg sync.WaitGroup
}

type Status struct {
	Source      string    `json:"source"`
	State       string    `json:"state"`
	LastSuccess time.Time `json:"last_success,omitempty"`
	Pending     int       `json:"pending"`
	Packages    int       `json:"packages"`
	LastError   string    `json:"last_error,omitempty"`
}

func NewEngine(cfg Config) *Engine {
	if cfg.MinInterval <= 0 {
		cfg.MinInterval = defaultMinInterval
	}
	e := &Engine{}
	if cfg.scheduleBackground == nil {
		// The default scheduler runs each background refresh on a tracked
		// goroutine with a bounded context. Wait() blocks on these, so the
		// hourly refresh actually completes and persists even when the
		// foreground command returns immediately from cache (otherwise the
		// goroutine is abandoned on process exit and the cache never updates).
		timeout := cfg.Timeout
		cfg.scheduleBackground = func(fn func(context.Context)) {
			e.wg.Add(1)
			go func() {
				defer e.wg.Done()
				ctx := context.Background()
				if timeout > 0 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, timeout)
					defer cancel()
				}
				fn(ctx)
			}()
		}
	}
	e.cfg = cfg
	return e
}

// Wait blocks until background refreshes scheduled through the default
// scheduler have finished. Each refresh is bounded by the configured Timeout,
// so this returns promptly when nothing is in flight and cannot hang on a slow
// upstream.
func (e *Engine) Wait() { e.wg.Wait() }

func (e *Engine) syncer() *inventorySyncer {
	return &inventorySyncer{cfg: e.cfg}
}

func (e *Engine) LoadIndex(ctx context.Context, onProgress malindex.IndexLoadProgress, onStatus malindex.IndexLoadStatus) (*malindex.MaliciousIndex, error) {
	idx, err := e.syncer().loadIndex(ctx, onProgress, onStatus)
	if err == nil && idx != nil {
		e.updateStatusFromManifest(idx.PackageCount())
	}
	return idx, err
}

func (e *Engine) StartBackground(ctx context.Context) {
	e.cfg.scheduleBackground(func(bg context.Context) {
		e.runBackground(bg)
	})
}

func (e *Engine) runBackground(ctx context.Context) {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return
	}
	e.running = true
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		e.running = false
		e.mu.Unlock()
	}()

	s := e.syncer()
	m, _ := loadManifest(e.cfg.CacheDir, inventorySource)
	if !s.needsRefresh(m) {
		return
	}
	idx, err := s.sync(ctx, nil, nil)
	if err == nil && idx != nil {
		e.updateStatusFromManifest(idx.PackageCount())
	}
}

func (e *Engine) StatusSnapshot() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.status.Packages > 0 || !e.status.LastSuccess.IsZero() {
		return e.status
	}
	m, err := loadManifest(e.cfg.CacheDir, inventorySource)
	if err != nil || m == nil {
		return e.status
	}
	packages := m.Compiled.PackageCount
	if packages == 0 && m.Compiled.Path != "" {
		if idx, ok := malindex.LoadCompiledIndexIfFresh(malindex.CompiledCachePath(e.cfg.CacheDir, "compiled")); ok {
			packages = idx.PackageCount()
		}
	}
	return Status{
		Source:      inventorySource,
		State:       m.Sync.State,
		LastSuccess: m.Sync.LastSuccess,
		Packages:    packages,
		LastError:   m.Sync.LastError,
	}
}

func (e *Engine) updateStatusFromManifest(packages int) {
	m, err := loadManifest(e.cfg.CacheDir, inventorySource)
	if err != nil || m == nil {
		return
	}
	e.mu.Lock()
	e.status = Status{
		Source:      inventorySource,
		State:       m.Sync.State,
		LastSuccess: m.Sync.LastSuccess,
		Packages:    packages,
		LastError:   m.Sync.LastError,
	}
	e.mu.Unlock()
}
