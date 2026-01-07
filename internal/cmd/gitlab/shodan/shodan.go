package shodan

import (
	"github.com/CompassSecurity/pipeleek/pkg/config"
	"github.com/CompassSecurity/pipeleek/pkg/gitlab/shodan"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func NewShodanCmd() *cobra.Command {
	shodanCmd := &cobra.Command{
		Use:     "shodan",
		Short:   "Query Shodan for GitLab instance IPs",
		Long:    "Query Shodan for IPs running GitLab instances",
		Example: `pipeleek gl shodan --json shodan_data.json`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := config.BindCommandFlags(cmd, "gitlab.shodan", nil); err != nil {
				log.Fatal().Err(err).Msg("Failed to bind flags")
			}

			if err := config.RequireConfigKeys("gitlab.shodan.json"); err != nil {
				log.Fatal().Err(err).Msg("required configuration missing")
			}

			shodanJsonFile := config.GetString("gitlab.shodan.json")

			shodan.RunShodan(shodanJsonFile)
		},
	}
	shodanCmd.Flags().String("json", "", "Path to Shodan JSON file")

	return shodanCmd
}
