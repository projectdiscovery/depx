package audit

import (
	"net/url"
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/depx/internal/github"
	"github.com/projectdiscovery/depx/internal/registry"
)

func enrichFinding(f Finding) Finding {
	src := f.Source
	if src == "" {
		src = f.Lockfile
	}
	if src != "" {
		if f.Source == "" {
			f.Source = src
		}
		if strings.HasPrefix(src, "github:") {
			if repo, ok := github.ParseRepo(src); ok {
				f.ProjectDir = src
				f.ProjectURL = repo.URL()
			}
		} else {
			f.ProjectDir = filepath.Dir(src)
			f.ProjectURL = fileURL(f.ProjectDir)
		}
	}
	f.PackageURL = registry.PackagePageURL(f.Ecosystem, f.Name)
	return f
}

func fileURL(path string) string {
	if path == "" {
		return ""
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return ""
	}
	return (&url.URL{Scheme: "file", Path: filepath.ToSlash(abs)}).String()
}
