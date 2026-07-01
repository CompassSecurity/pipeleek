package shodan

import (
	"github.com/CompassSecurity/pipeleek/pkg/config"
	"github.com/CompassSecurity/pipeleek/pkg/gitlab/shodan"
	"github.com/spf13/cobra"
)

var flagBindings = map[string]string{
	"json": "gitlab.shodan.json",
}

// RunShodan handles the shodan command execution
func RunShodan(cmd *cobra.Command, args []string) {
	config.NewCommandSetup(cmd).
		WithFlagBindings(flagBindings).
		RequireKeys("gitlab.shodan.json").
		MustBind()

	shodanJsonFile := config.GetString("gitlab.shodan.json")

	shodan.RunShodan(shodanJsonFile)
}

func NewShodanCmd() *cobra.Command {
	shodanCmd := &cobra.Command{
		Use:     "shodan",
		Short:   "Query Shodan for GitLab instance IPs",
		Long:    "Query Shodan for IPs running GitLab instances",
		Example: `pipeleek gl shodan --json shodan_data.json`,
		Run:     RunShodan,
	}
	shodanCmd.Flags().String("json", "", "Path to Shodan JSON file")

	return shodanCmd
}
