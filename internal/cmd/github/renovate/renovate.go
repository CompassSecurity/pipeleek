package renovate

import (
	"github.com/CompassSecurity/pipeleek/internal/cmd/github/renovate/autodiscovery"
	"github.com/CompassSecurity/pipeleek/internal/cmd/github/renovate/enum"
	"github.com/CompassSecurity/pipeleek/internal/cmd/github/renovate/lab"
	"github.com/CompassSecurity/pipeleek/internal/cmd/github/renovate/privesc"
	"github.com/CompassSecurity/pipeleek/pkg/config"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	githubApiToken string
	githubUrl      string
)

func NewRenovateRootCmd() *cobra.Command {
	renovateCmd := &cobra.Command{
		Use:   "renovate",
		Short: "Renovate related commands",
		Long:  "Commands to enumerate and exploit GitHub Renovate bot configurations.",
	}

	// Define PreRun to bind flags and validate configuration
	renovateCmd.PreRun = func(cmd *cobra.Command, args []string) {
		// Bind flags to config keys
		if err := config.BindCommandFlags(cmd, "github.renovate", map[string]string{
			"github": "github.url",
			"token":  "github.token",
		}); err != nil {
			log.Fatal().Err(err).Msg("Failed to bind flags to config")
		}

		// Get values from config (supports CLI flags, config file, and env vars)
		githubUrl = config.GetString("github.url")
		githubApiToken = config.GetString("github.token")

		// Validate required values
		if githubUrl == "" {
			log.Fatal().Msg("GitHub URL is required (use --github flag, config file, or PIPELEEK_GITHUB_URL env var)")
		}
		if githubApiToken == "" {
			log.Fatal().Msg("GitHub token is required (use --token flag, config file, or PIPELEEK_GITHUB_TOKEN env var)")
		}
	}

	renovateCmd.PersistentFlags().StringVarP(&githubUrl, "github", "g", "https://api.github.com", "GitHub API base URL")
	renovateCmd.PersistentFlags().StringVarP(&githubApiToken, "token", "t", "", "GitHub Personal Access Token")

	renovateCmd.AddCommand(enum.NewEnumCmd())
	renovateCmd.AddCommand(autodiscovery.NewAutodiscoveryCmd())
	renovateCmd.AddCommand(lab.NewLabCmd())
	renovateCmd.AddCommand(privesc.NewPrivescCmd())

	return renovateCmd
}
