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

var (
	labRepoName string
)

func NewLabCmd() *cobra.Command {
	labCmd := &cobra.Command{
		Use:   "lab",
		Short: "Set up a Renovate Bot testing lab on GitHub",
		Long:  "Creates a GitHub repository with Renovate Bot autodiscovery configuration enabled.",
		Example: `
# Create a Renovate testing lab repository
pipeleek gh renovate lab --token ghp_xxxxx --github https://api.github.com --repo-name renovate-lab
`,
		PreRun: func(cmd *cobra.Command, args []string) {
			// Bind parent flags to config
			if err := config.BindCommandFlags(cmd.Parent(), "github.renovate", map[string]string{
				"github": "github.url",
				"token":  "github.token",
			}); err != nil {
				log.Fatal().Err(err).Msg("Failed to bind parent flags")
			}
		},
		Run: func(cmd *cobra.Command, args []string) {
			if err := config.BindCommandFlags(cmd, "github.renovate.lab", nil); err != nil {
				log.Fatal().Err(err).Msg("Failed to bind flags to config")
			}

			// Get github URL and token from config (supports all three methods)
			githubUrl := config.GetString("github.url")
			githubApiToken := config.GetString("github.token")

			if githubUrl == "" {
				log.Fatal().Msg("GitHub URL is required (use --github flag, config file, or PIPELEEK_GITHUB_URL env var)")
			}
			if githubApiToken == "" {
				log.Fatal().Msg("GitHub token is required (use --token flag, config file, or PIPELEEK_GITHUB_TOKEN env var)")
			}

			// Get flags from config if not set via CLI
			if !cmd.Flags().Changed("repo-name") {
				labRepoName = config.GetString("github.renovate.lab.repo-name")
			}

			if labRepoName == "" {
				log.Fatal().Msg("Repository name is required (use --repo-name flag or PIPELEEK_GITHUB_RENOVATE_LAB_REPO_NAME env var)")
			}

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
		},
	}

	labCmd.Flags().StringVarP(&labRepoName, "repo-name", "r", "", "Name for the Renovate testing lab repository")
	if err := labCmd.MarkFlagRequired("repo-name"); err != nil {
		log.Fatal().Err(err).Msg("Failed to mark repo-name flag as required")
	}

	return labCmd
}
