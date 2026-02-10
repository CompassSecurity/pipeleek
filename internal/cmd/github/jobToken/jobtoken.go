package jobtoken

import (
	"strings"

	"github.com/CompassSecurity/pipeleek/internal/cmd/github/jobToken/exploit"
	"github.com/CompassSecurity/pipeleek/pkg/config"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	githubApiToken string
	githubUrl      string
)

func NewJobTokenRootCmd() *cobra.Command {
	jobTokenCmd := &cobra.Command{
		Use:   "jobToken",
		Short: "Job token related commands",
		Long:  "Commands to handle GitHub Actions CI/CD tokens (GITHUB_TOKEN) https://docs.github.com/en/actions/concepts/security/github_token",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			rootCmd := cmd.Root()
			if rootCmd != nil && rootCmd.PersistentPreRun != nil && rootCmd != cmd {
				rootCmd.PersistentPreRun(rootCmd, args)
			}

			if err := config.AutoBindFlags(cmd, map[string]string{
				"github": "github.url",
				"token":  "github.token",
			}); err != nil {
				log.Fatal().Err(err).Msg("Failed to bind command flags to configuration keys")
			}

			if err := config.RequireConfigKeys("github.url", "github.token"); err != nil {
				log.Fatal().Err(err).Msg("required configuration missing")
			}

			githubApiToken := config.GetString("github.token")
			if !strings.HasPrefix(githubApiToken, "ghs_") {
				log.Warn().Msg("Token does not have the expected GITHUB_TOKEN prefix (ghs_). This command is designed for GitHub Actions CI/CD tokens.")
			}

			return nil
		},
	}

	jobTokenCmd.PersistentFlags().StringVarP(&githubUrl, "github", "g", "", "GitHub API base URL")
	jobTokenCmd.PersistentFlags().StringVarP(&githubApiToken, "token", "t", "", "GitHub Actions CI/CD Token (GITHUB_TOKEN)")

	jobTokenCmd.AddCommand(exploit.NewExploitCmd())

	return jobTokenCmd
}
