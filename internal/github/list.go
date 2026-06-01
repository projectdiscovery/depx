package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const defaultRepoListPage = 100

type repoListItem struct {
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	Archived bool   `json:"archived"`
}

// ResolveRepos expands github subcommand targets into concrete repositories.
// With no inputs and an authenticated client, lists repositories the token can access.
func (c *Client) ResolveRepos(ctx context.Context, inputs []string, limit int) ([]Repo, error) {
	if len(inputs) == 0 {
		if c.Token == "" {
			return nil, fmt.Errorf("github target is required (set DEPX_GITHUB_TOKEN, GITHUB_TOKEN, or GH_TOKEN to scan accessible repositories)")
		}
		return c.ListAccessibleRepos(ctx, limit)
	}
	if limit <= 0 {
		limit = defaultRepoListPage
	}

	seen := make(map[string]struct{})
	out := make([]Repo, 0)
	for _, input := range inputs {
		target, err := ParseTarget(input)
		if err != nil {
			return nil, err
		}
		if target.IsOrg() {
			repos, err := c.ListOwnerRepos(ctx, target.Owner, limit)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", target.Owner, err)
			}
			for _, repo := range repos {
				key := repo.String()
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				out = append(out, repo)
			}
			continue
		}
		repo, _ := target.Repo()
		key := repo.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, repo)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no repositories matched")
	}
	return out, nil
}

// AuthenticatedLogin returns the GitHub username for the configured token.
func (c *Client) AuthenticatedLogin(ctx context.Context) (string, error) {
	if c.Token == "" {
		return "", fmt.Errorf("github token is required")
	}
	endpoint := fmt.Sprintf("%s/user", c.APIBase)
	body, statusCode, hdr, err := c.doRequestWithHeaders(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	if statusCode != http.StatusOK {
		return "", newAPIError(endpoint, statusCode, body, hdr)
	}
	var user struct {
		Login string `json:"login"`
	}
	if err := json.Unmarshal(body, &user); err != nil {
		return "", err
	}
	if user.Login == "" {
		return "", fmt.Errorf("github user login missing from response")
	}
	return user.Login, nil
}

// ListAccessibleRepos lists repositories the authenticated token can access.
func (c *Client) ListAccessibleRepos(ctx context.Context, limit int) ([]Repo, error) {
	if c.Token == "" {
		return nil, fmt.Errorf("github token is required")
	}
	q := url.Values{}
	q.Set("affiliation", "owner,collaborator,organization_member")
	q.Set("visibility", "all")
	q.Set("sort", "updated")
	return c.listRepos(ctx, fmt.Sprintf("%s/user/repos", c.APIBase), "", limit, q)
}

// ListOwnerRepos lists repositories for a GitHub org or user.
func (c *Client) ListOwnerRepos(ctx context.Context, owner string, limit int) ([]Repo, error) {
	if limit <= 0 {
		limit = defaultRepoListPage
	}
	q := url.Values{}
	q.Set("type", "all")
	repos, err := c.listRepos(ctx, fmt.Sprintf("%s/orgs/%s/repos", c.APIBase, url.PathEscape(owner)), owner, limit, q)
	if err == nil && len(repos) > 0 {
		return repos, nil
	}
	return c.listRepos(ctx, fmt.Sprintf("%s/users/%s/repos", c.APIBase, url.PathEscape(owner)), owner, limit, q)
}

func (c *Client) listRepos(ctx context.Context, endpoint, listOwner string, limit int, baseQuery url.Values) ([]Repo, error) {
	if limit <= 0 {
		limit = defaultRepoListPage
	}
	out := make([]Repo, 0, limit)
	page := 1
	for len(out) < limit {
		pageURL, err := url.Parse(endpoint)
		if err != nil {
			return nil, err
		}
		q := cloneValues(baseQuery)
		q.Set("per_page", fmt.Sprintf("%d", min(limit-len(out), defaultRepoListPage)))
		q.Set("page", fmt.Sprintf("%d", page))
		pageURL.RawQuery = q.Encode()

		body, statusCode, hdr, err := c.doRequestWithHeaders(ctx, http.MethodGet, pageURL.String(), nil)
		if err != nil {
			return nil, err
		}
		if statusCode == http.StatusNotFound {
			return nil, fmt.Errorf("not found")
		}
		if statusCode != http.StatusOK {
			return nil, newAPIError(pageURL.String(), statusCode, body, hdr)
		}

		var items []repoListItem
		if err := json.Unmarshal(body, &items); err != nil {
			return nil, err
		}
		if len(items) == 0 {
			break
		}
		for _, item := range items {
			if item.Archived || item.Name == "" {
				continue
			}
			owner, name := splitFullName(item.FullName, listOwner, item.Name)
			if owner == "" || name == "" {
				continue
			}
			out = append(out, Repo{Owner: owner, Name: name})
			if len(out) >= limit {
				return out, nil
			}
		}
		if len(items) < defaultRepoListPage {
			break
		}
		page++
	}
	return out, nil
}

func cloneValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for key, vals := range v {
		out[key] = append([]string(nil), vals...)
	}
	return out
}

func splitFullName(fullName, listOwner, fallbackName string) (string, string) {
	if fullName != "" {
		owner, name, ok := strings.Cut(fullName, "/")
		if ok && owner != "" && name != "" {
			return owner, name
		}
	}
	if listOwner != "" && fallbackName != "" {
		return listOwner, fallbackName
	}
	return "", fallbackName
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
