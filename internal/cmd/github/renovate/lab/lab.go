package lab

import (
	"context"
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkglab "github.com/CompassSecurity/pipeleek/pkg/github/renovate/lab"
	pkgscan "github.com/CompassSecurity/pipeleek/pkg/github/scan"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var flagBindings = map[string]string{
	"url":       "github.url",
	"token":     "github.token",
	"repo-name": "github.renovate.lab.repo_name",
}

// RunLabSetupCommand handles the lab command execution
func RunLabSetupCommand(cmd *cobra.Command, args []string) {
	config.NewCommandSetup(cmd).
		WithFlagBindings(flagBindings).
		RequireKeys("github.token", "github.renovate.lab.repo_name").
		MustBind()

	githubUrl := config.GetString("github.url")
	githubApiToken := config.GetString("github.token")
	labRepoName := config.GetString("github.renovate.lab.repo_name")

	client := pkgscan.SetupClient(githubApiToken, githubUrl)

	// Get authenticated user to use as owner
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	user, _, err := client.Users.Get(ctx, "")
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get authenticated user")
	}

	if err := pkglab.RunLabSetup(client, labRepoName, user.GetLogin()); err != nil {
		log.Fatal().Err(err).Msg("Failed to set up lab")
	}
}

func NewLabCmd() *cobra.Command {
	labCmd := &cobra.Command{
		Use:   "lab",
		Short: "Set up a Renovate Bot testing lab on GitHub",
		Long:  "Creates a GitHub repository with Renovate Bot autodiscovery configuration enabled.",
		Example: `
# Create a Renovate testing lab repository
pipeleek gh renovate lab --token ghp_xxxxx --url https://api.github.com --repo-name renovate-lab
`,
		Run: RunLabSetupCommand,
	}

	var labRepoName string

	labCmd.Flags().StringVarP(&labRepoName, "repo-name", "r", "", "Name for the Renovate testing lab repository")

	return labCmd
}
