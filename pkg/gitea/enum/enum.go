package enum

import (
	"fmt"

	"code.gitea.io/sdk/gitea"
	"github.com/rs/zerolog/log"
)

// RunEnum performs the enumeration of Gitea access rights.
func RunEnum(giteaURL, apiToken string) error {
	client, err := gitea.NewClient(giteaURL, gitea.SetToken(apiToken))
	if err != nil {
		return err
	}

	log.Info().Msg("Enumerating User")
	user, _, err := client.GetMyUserInfo()
	if err != nil {
		return err
	}

	if user == nil {
		return fmt.Errorf("failed fetching current user (nil response)")
	}

	log.Debug().Interface("user", user).Msg("Full user data structure")

	log.Warn().
		Int64("id", user.ID).
		Str("username", user.UserName).
		Str("fullName", user.FullName).
		Str("email", user.Email).
		Str("description", user.Description).
		Bool("isAdmin", user.IsAdmin).
		Bool("isActive", user.IsActive).
		Bool("restricted", user.Restricted).
		Msg("Current user")

	log.Info().Msg("Enumerating Organizations")

	orgPage := 1
	for {
		orgs, resp, err := client.ListMyOrgs(gitea.ListOrgsOptions{
			ListOptions: gitea.ListOptions{
				Page:     orgPage,
				PageSize: 50,
			},
		})

		if err != nil {
			log.Error().Stack().Err(err).Msg("Failed fetching organizations")
			break
		}

		for _, org := range orgs {
			orgPerms, _, err := client.GetOrgPermissions(org.Name, user.UserName)

			if err != nil {
				log.Debug().Str("org", org.Name).Err(err).Msg("Failed to get org permissions")
			}

			logEvent := log.Warn().
				Int64("id", org.ID).
				Str("name", org.Name).
				Str("fullName", org.FullName).
				Str("website", org.Website).
				Str("description", org.Description).
				Str("visibility", org.Visibility)

			log.Debug().Interface("org", org).Msg("Full organization data structure")

			if orgPerms != nil {
				logEvent = logEvent.
					Bool("isOwner", orgPerms.IsOwner).
					Bool("isAdmin", orgPerms.IsAdmin).
					Bool("canWrite", orgPerms.CanWrite).
					Bool("canRead", orgPerms.CanRead).
					Bool("canCreateRepo", orgPerms.CanCreateRepository)
			}

			logEvent.Msg("Organization")
			log.Debug().Any("full_org_permissions", orgPerms).Msg("Full Organization permissions details")

			repoPage := 1
			for {
				orgRepos, repoResp, err := client.ListOrgRepos(org.Name, gitea.ListOrgReposOptions{
					ListOptions: gitea.ListOptions{
						Page:     repoPage,
						PageSize: 50,
					},
				})

				if err != nil {
					log.Debug().Str("org", org.Name).Err(err).Msg("Failed to list org repositories")
					break
				}

				for _, repo := range orgRepos {
					logRepo := log.Warn().
						Int64("id", repo.ID).
						Str("name", repo.Name).
						Str("fullName", repo.FullName).
						Str("owner", repo.Owner.UserName).
						Str("description", repo.Description).
						Bool("private", repo.Private).
						Bool("archived", repo.Archived).
						Str("url", repo.HTMLURL)
					log.Debug().Interface("repo", repo).Msg("Full organization repository data structure")

					if repo.Permissions != nil {
						logRepo = logRepo.
							Bool("admin", repo.Permissions.Admin).
							Bool("push", repo.Permissions.Push).
							Bool("pull", repo.Permissions.Pull)
					}

					logRepo.Msg("Organization Repository")
					log.Debug().Any("full_repo_permissions", repo.Permissions).Msg("Full Repository permissions details")
				}

				if repoResp == nil || repoResp.NextPage == 0 {
					break
				}

				repoPage = repoResp.NextPage
			}
		}

		if resp == nil || resp.NextPage == 0 {
			break
		}

		orgPage = resp.NextPage
	}

	log.Info().Msg("Enumerating User Repositories")

	repoPage := 1
	for {
		repos, resp, err := client.ListMyRepos(gitea.ListReposOptions{
			ListOptions: gitea.ListOptions{
				Page:     repoPage,
				PageSize: 50,
			},
		})
		if err != nil {
			log.Error().Stack().Err(err).Msg("Failed fetching user repositories")
			break
		}

		for _, repo := range repos {
			logRepo := log.Warn().
				Int64("id", repo.ID).
				Str("name", repo.Name).
				Str("fullName", repo.FullName).
				Str("owner", repo.Owner.UserName).
				Str("description", repo.Description).
				Bool("private", repo.Private).
				Bool("archived", repo.Archived).
				Str("url", repo.HTMLURL)
			log.Debug().Interface("repo", repo).Msg("Full user repository data structure")

			if repo.Permissions != nil {
				logRepo = logRepo.
					Bool("admin", repo.Permissions.Admin).
					Bool("push", repo.Permissions.Push).
					Bool("pull", repo.Permissions.Pull)
			}

			logRepo.Msg("User Repository")
			log.Debug().Any("full_repo_permissions", repo.Permissions).Msg("Full Repository permissions details")
		}

		if resp == nil || resp.NextPage == 0 {
			break
		}
		repoPage = resp.NextPage
	}

	log.Info().Msg("Done")
	return nil
}
