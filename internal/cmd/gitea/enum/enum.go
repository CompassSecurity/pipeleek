package enum

import (
	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgenum "github.com/CompassSecurity/pipeleek/pkg/gitea/enum"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func NewEnumCmd() *cobra.Command {
	enumCmd := &cobra.Command{
		Use:     "enum",
		Short:   "Enumerate access of a Gitea token",
		Long:    "Enumerate access rights of a Gitea access token by retrieving the authenticated user's information, organizations with access levels, and all accessible repositories with permissions.",
		Example: `pipeleek gitea enum --token [tokenval] --gitea https://gitea.mycompany.com`,
		Run:     Enum,
	}

	return enumCmd
}

func Enum(cmd *cobra.Command, args []string) {
	if err := config.AutoBindFlags(cmd, map[string]string{
		"gitea": "gitea.url",
		"token": "gitea.token",
	}); err != nil {
		log.Fatal().Err(err).Msg("Failed to bind command flags to configuration keys")
	}

	if err := config.RequireConfigKeys("gitea.url", "gitea.token"); err != nil {
		log.Fatal().Err(err).Msg("required configuration missing")
	}

	giteaUrl := config.GetString("gitea.url")
	giteaApiToken := config.GetString("gitea.token")

	if err := pkgenum.RunEnum(giteaUrl, giteaApiToken); err != nil {
		log.Fatal().Stack().Err(err).Msg("Enumeration failed")
	}
}
