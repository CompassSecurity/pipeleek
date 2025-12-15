package util

import (
	"code.gitea.io/sdk/gitea"
	"github.com/rs/zerolog/log"
)

// GiteaVersion represents Gitea version information
type GiteaVersion struct {
	Version string
}

// DetermineVersion retrieves the Gitea instance version using the API
func DetermineVersion(giteaUrl string, apiToken string) *GiteaVersion {
	client, err := gitea.NewClient(giteaUrl, gitea.SetToken(apiToken))
	if err != nil {
		log.Warn().Err(err).Msg("Failed to create Gitea client")
		return &GiteaVersion{Version: "none"}
	}

	version, _, err := client.ServerVersion()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to fetch Gitea version")
		return &GiteaVersion{Version: "none"}
	}

	return &GiteaVersion{Version: version}
}
