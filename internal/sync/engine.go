package sync

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/projectdiscovery/depx/internal/osv"
	"github.com/projectdiscovery/depx/internal/pd"
)

const defaultMinInterval = 5 * time.Minute

type Config struct {
	CacheDir  string
	UserAgent string
	Timeout   time.Duration
	Source    string
	MinInterval time.Duration

	scheduleBackground func(fn func(context.Context))
}

type Engine struct {
	cfg Config

	mu      sync.Mutex
	running bool
	status  Status
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
	if cfg.scheduleBackground == nil {
		cfg.scheduleBackground = func(fn func(context.Context)) {
			go fn(context.Background())
		}
	}
	return &Engine{cfg: cfg}
}

func (e *Engine) LoadIndex(ctx context.Context, onProgress osv.IndexLoadProgress, onStatus osv.IndexLoadStatus) (*osv.MaliciousIndex, error) {
	switch e.cfg.Source {
	case "pd":
		return e.loadPDIndex(ctx, onProgress, onStatus)
	default:
		s := &osvSyncer{cfg: e.cfg}
		idx, err := s.loadIndex(ctx, false, onProgress, onStatus)
		if err == nil && idx != nil {
			e.updateStatusFromManifest("osv", idx.PackageCount())
		}
		return idx, err
	}
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

	switch e.cfg.Source {
	case "pd":
		_, _ = e.loadPDIndex(ctx, nil, nil)
	default:
		s := &osvSyncer{cfg: e.cfg}
		m, _ := loadManifest(e.cfg.CacheDir, "osv")
		if m == nil {
			m = newManifest("osv")
		}
		if !s.shouldSync(m) && m.countPending() == 0 {
			return
		}
		idx, err := s.runSync(ctx, m, nil, nil)
		if err == nil && idx != nil {
			e.updateStatusFromManifest("osv", idx.PackageCount())
		}
	}
}

func (e *Engine) StatusSnapshot() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.status.Packages > 0 || !e.status.LastSuccess.IsZero() {
		return e.status
	}
	m, err := loadManifest(e.cfg.CacheDir, e.cfg.Source)
	if err != nil || m == nil {
		return e.status
	}
	packages := m.Compiled.PackageCount
	if packages == 0 && m.Compiled.Path != "" {
		if idx, ok := osv.LoadCompiledIndexIfFresh(osv.CompiledCachePath(e.cfg.CacheDir, compiledName(e.cfg.Source))); ok {
			packages = idx.PackageCount()
		}
	}
	return Status{
		Source:      e.cfg.Source,
		State:       m.Sync.State,
		LastSuccess: m.Sync.LastSuccess,
		Pending:     m.countPending(),
		Packages:    packages,
		LastError:   m.Sync.LastError,
	}
}

func compiledName(source string) string {
	if source == "pd" {
		return "pd_compiled"
	}
	return "compiled"
}

func (e *Engine) updateStatusFromManifest(source string, packages int) {
	m, err := loadManifest(e.cfg.CacheDir, source)
	if err != nil {
		return
	}
	e.mu.Lock()
	e.status = Status{
		Source:      source,
		State:       m.Sync.State,
		LastSuccess: m.Sync.LastSuccess,
		Pending:     m.countPending(),
		Packages:    packages,
		LastError:   m.Sync.LastError,
	}
	e.mu.Unlock()
}

func (e *Engine) loadPDIndex(ctx context.Context, onProgress osv.IndexLoadProgress, onStatus osv.IndexLoadStatus) (*osv.MaliciousIndex, error) {
	cachePath := osv.CompiledCachePath(e.cfg.CacheDir, "pd_compiled")
	if idx, ok := osv.LoadCompiledIndexIfFresh(cachePath); ok {
		if onProgress != nil {
			onProgress(idx.PackageCount(), idx.PackageCount())
		}
		e.schedulePDSync(ctx)
		return idx, nil
	}

	client, err := pd.NewClient(e.cfg.UserAgent, e.cfg.Timeout)
	if err != nil {
		return nil, err
	}
	idx, err := syncPDIndex(ctx, client, e.cfg.CacheDir, onProgress, onStatus)
	if err != nil {
		return nil, err
	}
	e.updateStatusFromManifest("pd", idx.PackageCount())
	return idx, nil
}

func (e *Engine) schedulePDSync(ctx context.Context) {
	m, _ := loadManifest(e.cfg.CacheDir, "pd")
	if m != nil && !m.Sync.LastSuccess.IsZero() && time.Since(m.Sync.LastSuccess) < e.cfg.MinInterval {
		return
	}
	e.cfg.scheduleBackground(func(bg context.Context) {
		client, err := pd.NewClient(e.cfg.UserAgent, e.cfg.Timeout)
		if err != nil {
			return
		}
		idx, err := syncPDIndex(bg, client, e.cfg.CacheDir, nil, nil)
		if err == nil && idx != nil {
			e.updateStatusFromManifest("pd", idx.PackageCount())
		}
	})
}

func syncPDIndex(ctx context.Context, client *pd.Client, cacheDir string, onProgress osv.IndexLoadProgress, onStatus osv.IndexLoadStatus) (*osv.MaliciousIndex, error) {
	if onStatus != nil {
		onStatus("Fetching malicious package corpus from PD API…")
	}
	idx := osv.NewEmptyMaliciousIndex()
	const pageSize = 1000
	var loaded int
	var corpusTotal int
	page := 1
	for {
		res, err := client.ListPackagesEnvelope(ctx, pd.ListPackagesParams{
			Page: page, PerPage: pageSize, Withdrawn: "exclude",
		})
		if err != nil {
			return nil, err
		}
		if corpusTotal == 0 && res.Meta.Total > 0 {
			corpusTotal = res.Meta.Total
		}
		if len(res.Packages) == 0 {
			break
		}
		for _, pkg := range res.Packages {
			idx.AddListing(pkg.Ecosystem, pkg.PkgName, pkg.MalID, pkg.Summary, pkg.AllVersions, pkg.AffectedVersions, pkg.Published, pkg.Modified)
			loaded++
			if onProgress != nil {
				total := corpusTotal
				if total == 0 {
					total = loaded
				}
				onProgress(loaded, total)
			}
		}
		if res.Meta.TotalPages > 0 && page >= res.Meta.TotalPages {
			break
		}
		page++
	}
	path := osv.CompiledCachePath(cacheDir, "pd_compiled")
	_ = osv.SaveCompiledIndex(path, corpusTotal, idx)
	m := newManifest("pd")
	m.Compiled = CompiledState{
		Path:         "mal/pd_compiled.json",
		EntryCount:   corpusTotal,
		PackageCount: idx.PackageCount(),
		BuiltAt:      time.Now().UTC(),
	}
	m.Sync.State = "idle"
	m.Sync.LastSuccess = time.Now().UTC()
	_ = saveManifest(cacheDir, m)
	if onStatus != nil {
		onStatus(fmt.Sprintf("Malicious package index ready (%d packages)", idx.PackageCount()))
	}
	return idx, nil
}
