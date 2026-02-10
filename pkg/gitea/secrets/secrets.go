package secrets

import (
	"fmt"

	"code.gitea.io/sdk/gitea"
	"github.com/rs/zerolog/log"
)

type Config struct {
	URL   string
	Token string
}

// clientContext holds both the SDK client and configuration
type clientContext struct {
	client *gitea.Client
	token  string
	url    string
}

func ListAllSecrets(cfg Config) error {
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

	// Fetch organization secrets
	orgs, err := fetchOrganizations(ctx.client)
	if err != nil {
		return fmt.Errorf("failed to fetch organizations: %w", err)
	}

	log.Info().Int("count", len(orgs)).Msg("Found organizations")

	for _, org := range orgs {
		if err := fetchOrgSecrets(ctx.client, org.Name); err != nil {
			log.Warn().Err(err).Str("org", org.Name).Msg("Failed to fetch organization secrets")
		}
	}

	// Fetch repository secrets for all repos
	for _, repo := range repos {
		if err := fetchRepoSecrets(ctx.client, repo.Owner.UserName, repo.Name); err != nil {
			log.Warn().Err(err).Str("owner", repo.Owner.UserName).Str("repo", repo.Name).Msg("Failed to fetch repository secrets")
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

func fetchOrgSecrets(client *gitea.Client, orgName string) error {
	page := 1
	pageSize := 50

	for {
		secrets, resp, err := client.ListOrgActionSecret(orgName, gitea.ListOrgActionSecretOption{
			ListOptions: gitea.ListOptions{
				Page:     page,
				PageSize: pageSize,
			},
		})
		if err != nil {
			return err
		}

		for _, s := range secrets {
			log.Info().
				Str("org", orgName).
				Str("secret_name", s.Name).
				Str("type", "organization").
				Msg("Secret")
		}

		if resp == nil || len(secrets) < pageSize {
			break
		}
		page++
	}

	return nil
}

func fetchRepoSecrets(client *gitea.Client, owner, repo string) error {
	page := 1
	pageSize := 50

	for {
		secrets, resp, err := client.ListRepoActionSecret(owner, repo, gitea.ListRepoActionSecretOption{
			ListOptions: gitea.ListOptions{
				Page:     page,
				PageSize: pageSize,
			},
		})
		if err != nil {
			return err
		}

		for _, s := range secrets {
			log.Info().
				Str("org", owner).
				Str("repo", repo).
				Str("secret_name", s.Name).
				Str("type", "repository").
				Msg("Secret")
		}

		if resp == nil || len(secrets) < pageSize {
			break
		}
		page++
	}

	return nil
}
