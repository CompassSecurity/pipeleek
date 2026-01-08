package secrets

import (
	"github.com/CompassSecurity/pipeleek/pkg/config"
	"github.com/CompassSecurity/pipeleek/pkg/gitea/secrets"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func NewSecretsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secrets",
		Short: "List all Gitea Actions secrets from groups and repositories",
		Long:  `Fetches and logs all Actions secrets from organizations and their repositories in Gitea.`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := config.AutoBindFlags(cmd, map[string]string{
				"gitea": "gitea.url",
				"token": "gitea.token",
			}); err != nil {
				log.Fatal().Err(err).Msg("Failed to bind command flags to configuration keys")
			}

			if err := config.RequireConfigKeys("gitea.url", "gitea.token"); err != nil {
				log.Fatal().Err(err).Msg("required configuration missing")
			}

			url := config.GetString("gitea.url")
			token := config.GetString("gitea.token")

			cfg := secrets.Config{
				URL:   url,
				Token: token,
			}

			if err := secrets.ListAllSecrets(cfg); err != nil {
				log.Fatal().Err(err).Msg("Failed to list secrets")
			}
		},
	}

	return cmd
}
