package audit

import (
	"path/filepath"
)

type Progress struct {
	OnDiscover   func(found int, currentPath string)
	OnDiscovered func(lockfileCount int, root string)
	OnLockfile   func(index, total int, path string, depCount int)
	OnSource     func(index, total int, path string, sourceType SourceType, depCount int)
	OnIndex      func(loaded, total int)
	OnQuery      func(checked, total int, lockfile string)
	OnFinding    func(Finding)
	OnStatus     func(msg string)
	OnComplete   func()
}

func (p *Progress) discover(found int, currentPath string) {
	if p != nil && p.OnDiscover != nil {
		p.OnDiscover(found, currentPath)
	}
}

func (p *Progress) discovered(lockfileCount int, root string) {
	if p != nil && p.OnDiscovered != nil {
		p.OnDiscovered(lockfileCount, root)
	}
}

func (p *Progress) lockfile(index, total int, path string, depCount int) {
	if p != nil && p.OnLockfile != nil {
		p.OnLockfile(index, total, path, depCount)
	}
}

func (p *Progress) source(index, total int, path string, sourceType SourceType, depCount int) {
	if p != nil && p.OnSource != nil {
		p.OnSource(index, total, path, sourceType, depCount)
		return
	}
	p.lockfile(index, total, path, depCount)
}

func (p *Progress) index(loaded, total int) {
	if p != nil && p.OnIndex != nil {
		p.OnIndex(loaded, total)
	}
}

func (p *Progress) query(checked, total int, lockfile string) {
	if p != nil && p.OnQuery != nil {
		p.OnQuery(checked, total, lockfile)
	}
}

func (p *Progress) finding(f Finding) {
	if p != nil && p.OnFinding != nil {
		p.OnFinding(f)
	}
}

func (p *Progress) status(msg string) {
	if p != nil && p.OnStatus != nil {
		p.OnStatus(msg)
	}
}

func (p *Progress) complete() {
	if p != nil && p.OnComplete != nil {
		p.OnComplete()
	}
}

type extractJob struct {
	root       string
	path       string
	sourceType SourceType
	label      string
}

func collectExtractJobs(targets []auditTarget) []extractJob {
	jobs := make([]extractJob, 0)
	for _, target := range targets {
		for _, path := range target.pathsToExtract {
			sourceType, ok := sourceTypeForPath(path)
			if !ok {
				sourceType = SourceTypeLockfile
			}
			jobs = append(jobs, extractJob{
				root:       filepath.Dir(path),
				path:       path,
				sourceType: sourceType,
				label:      target.sourceLabels[path],
			})
		}
	}
	return jobs
}
