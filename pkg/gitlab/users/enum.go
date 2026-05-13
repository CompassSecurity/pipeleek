package users

import (
	"github.com/CompassSecurity/pipeleek/pkg/gitlab/util"
	"github.com/rs/zerolog/log"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func RunEnum(gitlabURL, token string) {
	git, err := util.GetGitlabClient(token, gitlabURL)
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Failed creating gitlab client")
	}

	log.Info().Msg("Enumerating GitLab users")

	totalUsers := 0
	page := int64(1)
	for page != -1 {
		users, nextPage, err := listUsers(git, page)
		if err != nil {
			log.Fatal().Stack().Err(err).Msg("Failed listing GitLab users")
		}

		for _, user := range users {
			if user == nil {
				continue
			}

			totalUsers++
			log.Info().
				Int64("id", user.ID).
				Str("username", user.Username).
				Str("name", user.Name).
				Str("publicEmail", user.PublicEmail).
				Str("profile", user.WebURL).
				Str("state", user.State).
				Bool("bot", user.Bot).
				Bool("admin", user.IsAdmin).
				Bool("external", user.External).
				Bool("privateProfile", user.PrivateProfile).
				Msg("GitLab user")
			log.Debug().Interface("full_user", user).Msg("Full User details")
		}

		page = nextPage
	}

	log.Info().Int("users", totalUsers).Msg("GitLab user enumeration complete")
}

func listUsers(git *gitlab.Client, page int64) ([]*gitlab.User, int64, error) {
	users, resp, err := git.Users.ListUsers(&gitlab.ListUsersOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: 100,
			Page:    page,
		},
	})
	if err != nil {
		return nil, -1, err
	}

	nextPage := int64(-1)
	if resp != nil && resp.NextPage > 0 {
		nextPage = resp.NextPage
	}

	return users, nextPage, nil
}
