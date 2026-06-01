package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
