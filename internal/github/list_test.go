package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestResolveReposSingle(t *testing.T) {
	client := NewClient("depx-test", "", 0)
	repos, err := client.ResolveRepos(context.Background(), []string{"owner/repo"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 1 || repos[0].String() != "owner/repo" {
		t.Fatalf("got %+v", repos)
	}
}

func TestResolveReposDedupe(t *testing.T) {
	client := NewClient("depx-test", "", 0)
	repos, err := client.ResolveRepos(context.Background(), []string{
		"owner/repo",
		"https://github.com/owner/repo",
	}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 1 {
		t.Fatalf("expected 1 repo, got %d", len(repos))
	}
}

func TestListOwnerRepos(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme/repos":
			_ = json.NewEncoder(w).Encode([]repoListItem{
				{FullName: "acme/one", Name: "one"},
				{FullName: "acme/two", Name: "two", Archived: true},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := NewClient("depx-test", "", 0)
	client.APIBase = srv.URL
	repos, err := client.ListOwnerRepos(context.Background(), "acme", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 1 || repos[0].String() != "acme/one" {
		t.Fatalf("got %+v", repos)
	}
}

// TestListOwnerReposPaginatesPastArchived guards against the pagination bug
// where per_page was sized to the remaining count: because archived repos are
// filtered out, results grew slower than rows consumed, per_page shrank, and a
// short (but non-final) page tripped the end-of-results check early. With a
// large org whose pages are heavily archived (e.g. github.com/google), this
// truncated the result far below the requested limit.
func TestListOwnerReposPaginatesPastArchived(t *testing.T) {
	const total = 250
	pool := make([]repoListItem, total)
	for i := 0; i < total; i++ {
		n := i + 1
		pool[i] = repoListItem{
			FullName: fmt.Sprintf("big/repo-%d", n),
			Name:     fmt.Sprintf("repo-%d", n),
			Archived: n%2 == 0, // half archived, interspersed across pages
		}
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/orgs/big/repos" {
			http.NotFound(w, r)
			return
		}
		perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
		if perPage <= 0 {
			perPage = 30
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page <= 0 {
			page = 1
		}
		start := (page - 1) * perPage
		if start >= len(pool) {
			_ = json.NewEncoder(w).Encode([]repoListItem{})
			return
		}
		end := start + perPage
		if end > len(pool) {
			end = len(pool)
		}
		_ = json.NewEncoder(w).Encode(pool[start:end])
	}))
	defer srv.Close()

	client := NewClient("depx-test", "", 0)
	client.APIBase = srv.URL
	repos, err := client.ListOwnerRepos(context.Background(), "big", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 100 {
		t.Fatalf("expected 100 non-archived repos via pagination, got %d", len(repos))
	}
	for _, repo := range repos {
		var n int
		if _, err := fmt.Sscanf(repo.Name, "repo-%d", &n); err == nil && n%2 == 0 {
			t.Fatalf("archived repo leaked into results: %s", repo.String())
		}
	}
}

func TestResolveReposOrg(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/orgs/acme/repos" {
			_ = json.NewEncoder(w).Encode([]repoListItem{
				{FullName: "acme/app", Name: "app"},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := NewClient("depx-test", "", 0)
	client.APIBase = srv.URL
	repos, err := client.ResolveRepos(context.Background(), []string{"acme"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 1 || repos[0].String() != "acme/app" {
		t.Fatalf("got %+v", repos)
	}
}

func TestResolveReposNoArgsRequiresToken(t *testing.T) {
	client := NewClient("depx-test", "", 0)
	_, err := client.ResolveRepos(context.Background(), nil, 10)
	if err == nil || !strings.Contains(err.Error(), "github target is required") {
		t.Fatalf("expected token/target error, got %v", err)
	}
}

func TestListAccessibleRepos(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user/repos":
			if got := r.URL.Query().Get("affiliation"); got != "owner,collaborator,organization_member" {
				t.Fatalf("affiliation = %q", got)
			}
			_ = json.NewEncoder(w).Encode([]repoListItem{
				{FullName: "octo/private-app", Name: "private-app"},
				{FullName: "acme/shared", Name: "shared", Archived: true},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := NewClient("depx-test", "token", 0)
	client.APIBase = srv.URL
	repos, err := client.ListAccessibleRepos(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 1 || repos[0].String() != "octo/private-app" {
		t.Fatalf("got %+v", repos)
	}
}

func TestAuthenticatedLogin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/user" {
			_ = json.NewEncoder(w).Encode(map[string]string{"login": "octocat"})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := NewClient("depx-test", "token", 0)
	client.APIBase = srv.URL
	login, err := client.AuthenticatedLogin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if login != "octocat" {
		t.Fatalf("login = %q", login)
	}
}
