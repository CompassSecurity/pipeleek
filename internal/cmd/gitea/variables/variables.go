package variables

import (
	"github.com/CompassSecurity/pipeleek/pkg/config"
	"github.com/CompassSecurity/pipeleek/pkg/gitea/variables"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var flagBindings = map[string]string{
	"url": "gitea.url",
	"token": "gitea.token",
}

func NewVariablesCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "variables",
		Short: "List all Gitea Actions variables from groups and repositories",
		Long:  `Fetches and logs all Actions variables from organizations and their repositories in Gitea.`,
		Run: func(cmd *cobra.Command, args []string) {
			config.NewCommandSetup(cmd).
				WithFlagBindings(flagBindings).
				RequireKeys("gitea.url", "gitea.token").
				MustBind()

			url := config.GetString("gitea.url")
			token := config.GetString("gitea.token")

			cfg := variables.Config{
				URL:   url,
				Token: token,
			}

			if err := variables.ListAllVariables(cfg); err != nil {
				log.Fatal().Err(err).Msg("Failed to list variables")
			}
		},
	}

	return cmd
}
