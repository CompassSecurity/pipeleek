package variables

import (
	"encoding/json"
	"fmt"
	"io"

	"code.gitea.io/sdk/gitea"
	"github.com/CompassSecurity/pipeleek/pkg/httpclient"
	"github.com/rs/zerolog/log"
)

type Config struct {
	URL   string
	Token string
}

// clientContext holds both the SDK client and configuration needed for direct API calls
type clientContext struct {
	client *gitea.Client
	token  string
	url    string
}

func ListAllVariables(cfg Config) error {
	ctx, err := createClientContext(cfg)
	if err != nil {
		return fmt.Errorf("failed to create Gitea client: %w", err)
	}

	// Fetch all repositories user has access to
	repos, err := fetchAllRepositories(ctx.client)
	if err != nil {
		return fmt.Errorf("failed to fetch repositories: %w", err)
	}

	log.Info().Int("count", len(repos)).Msg("Found repositories")

	// Fetch organization variables
	orgs, err := fetchOrganizations(ctx.client)
	if err != nil {
		return fmt.Errorf("failed to fetch organizations: %w", err)
	}

	log.Info().Int("count", len(orgs)).Msg("Found organizations")

	for _, org := range orgs {
		if err := fetchOrgVariables(ctx.client, org.Name); err != nil {
			log.Warn().Err(err).Str("org", org.Name).Msg("Failed to fetch organization variables")
		}
	}

	// Fetch repository variables for all repos
	for _, repo := range repos {
		if err := fetchRepoVariables(ctx, repo.Owner.UserName, repo.Name); err != nil {
			log.Warn().Err(err).Str("owner", repo.Owner.UserName).Str("repo", repo.Name).Msg("Failed to fetch repository variables")
		}
	}

	return nil
}

func createClientContext(cfg Config) (*clientContext, error) {
	client, err := gitea.NewClient(cfg.URL, gitea.SetToken(cfg.Token))
	if err != nil {
		return nil, err
	}

	return &clientContext{
		client: client,
		token:  cfg.Token,
		url:    cfg.URL,
	}, nil
}

func fetchOrganizations(client *gitea.Client) ([]*gitea.Organization, error) {
	var allOrgs []*gitea.Organization
	page := 1
	pageSize := 50

	for {
		orgs, resp, err := client.ListMyOrgs(gitea.ListOrgsOptions{
			ListOptions: gitea.ListOptions{
				Page:     page,
				PageSize: pageSize,
			},
		})
		if err != nil {
			return nil, err
		}

		allOrgs = append(allOrgs, orgs...)

		if resp == nil || len(orgs) < pageSize {
			break
		}
		page++
	}

	return allOrgs, nil
}

func fetchAllRepositories(client *gitea.Client) ([]*gitea.Repository, error) {
	var allRepos []*gitea.Repository
	page := 1
	pageSize := 50

	for {
		repos, resp, err := client.ListMyRepos(gitea.ListReposOptions{
			ListOptions: gitea.ListOptions{
				Page:     page,
				PageSize: pageSize,
			},
		})
		if err != nil {
			return nil, err
		}

		allRepos = append(allRepos, repos...)

		if resp == nil || len(repos) < pageSize {
			break
		}
		page++
	}

	return allRepos, nil
}

func fetchOrgVariables(client *gitea.Client, orgName string) error {
	page := 1
	pageSize := 50

	for {
		variables, resp, err := client.ListOrgActionVariable(orgName, gitea.ListOrgActionVariableOption{
			ListOptions: gitea.ListOptions{
				Page:     page,
				PageSize: pageSize,
			},
		})
		if err != nil {
			return err
		}

		for _, v := range variables {
			log.Info().
				Str("org", orgName).
				Str("variable_name", v.Name).
				Str("type", "organization").
				Str("value", v.Data).
				Msg("Variable")
		}

		if resp == nil || len(variables) < pageSize {
			break
		}
		page++
	}

	return nil
}

// fetchRepoVariables fetches all variables for a specific repository using the Gitea API.
// The SDK doesn't provide a ListRepoActionVariable method, so we use a direct API call.
func fetchRepoVariables(ctx *clientContext, owner, repo string) error {
	page := 1
	pageSize := 50

	for {
		variables, err := listRepoActionVariables(ctx, owner, repo, page, pageSize)
		if err != nil {
			return err
		}

		for _, v := range variables {
			log.Info().
				Str("org", owner).
				Str("repo", repo).
				Str("variable_name", v.Name).
				Str("type", "repository").
				Str("value", v.Value).
				Msg("Variable")
		}

		if len(variables) < pageSize {
			break
		}
		page++
	}

	return nil
}

// listRepoActionVariables calls the Gitea API directly to list repository action variables.
// This implements the missing SDK method by making a direct HTTP request using pkg/httpclient.
func listRepoActionVariables(ctx *clientContext, owner, repo string, page, pageSize int) ([]*gitea.RepoActionVariable, error) {
	url := fmt.Sprintf("%s/api/v1/repos/%s/%s/actions/variables?page=%d&limit=%d", ctx.url, owner, repo, page, pageSize)

	authHeaders := map[string]string{"Authorization": "token " + ctx.token}
	httpClient := httpclient.GetPipeleekHTTPClient("", nil, authHeaders)

	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var variables []*gitea.RepoActionVariable
	if err := json.Unmarshal(body, &variables); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return variables, nil
}
