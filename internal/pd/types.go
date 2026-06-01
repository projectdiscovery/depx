package pd

import "time"

type Meta struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	Total      int `json:"total"`
	TotalPages int `json:"total_pages"`
}

type APIErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Status  int    `json:"status"`
}

type Package struct {
	MalID            string
	Ecosystem        string
	PkgName          string
	PURL             string
	Source           string
	Severity         string
	AllVersions      bool
	AffectedVersions []string
	Published        time.Time
	Modified         time.Time
	Withdrawn        string
	Aliases          []string
	References       []string
	Summary          string
	IsOSV            bool
	OSVURL           string
}

type ListPackagesParams struct {
	Page      int
	PerPage   int
	Ecosystem string
	Source    string
	Query     string
	Withdrawn string // exclude|only|include
}

type ListPackagesResult struct {
	Packages []Package
	Meta     Meta
}
