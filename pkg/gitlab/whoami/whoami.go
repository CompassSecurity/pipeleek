package whoami

import (
	"strings"

	"github.com/CompassSecurity/pipeleek/pkg/gitlab/util"
	"github.com/rs/zerolog/log"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// Result contains the whoami response details.
type Result struct {
	User  *gitlab.User
	Token *util.SelfToken
}

// RunWhoAmI fetches and prints current user and current token details.
func RunWhoAmI(gitlabURL string, gitlabAPIToken string) {
	result, err := FetchWhoAmI(gitlabURL, gitlabAPIToken)
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Failed fetching GitLab whoami details")
	}

	log.Info().
		Str("username", result.User.Username).
		Str("name", result.User.Name).
		Str("email", result.User.Email).
		Bool("admin", result.User.IsAdmin).
		Bool("bot", result.User.Bot).
		Msg("Current user")
	log.Debug().Interface("full_user", result.User).Msg("Full user details")

	if result.Token != nil {
		log.Info().
			Int("id", result.Token.ID).
			Str("name", result.Token.Name).
			Bool("revoked", result.Token.Revoked).
			Time("created", result.Token.CreatedAt).
			Str("description", result.Token.Description).
			Str("scopes", strings.Join(result.Token.Scopes, ",")).
			Int("userId", result.Token.UserID).
			Time("lastUsedAt", result.Token.LastUsedAt).
			Bool("active", result.Token.Active).
			Str("expiresAt", result.Token.ExpiresAt).
			Str("lastUsedIps", strings.Join(result.Token.LastUsedIps, ",")).
			Msg("Current token")
		log.Debug().Interface("full_token", result.Token).Msg("Full token details")
	}
}

// FetchWhoAmI retrieves the current GitLab user and token details.
func FetchWhoAmI(gitlabURL string, gitlabAPIToken string) (*Result, error) {
	git, err := util.GetGitlabClient(gitlabAPIToken, gitlabURL)
	if err != nil {
		return nil, err
	}

	user, _, err := git.Users.CurrentUser()
	if err != nil {
		return nil, err
	}

	token, err := util.FetchCurrentToken(gitlabURL, gitlabAPIToken)
	if err != nil {
		return nil, err
	}

	return &Result{User: user, Token: token}, nil
}
