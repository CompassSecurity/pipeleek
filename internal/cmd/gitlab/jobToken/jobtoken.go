package jobtoken

import (
	"strings"

	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/jobToken/exploit"
	"github.com/CompassSecurity/pipeleek/pkg/config"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	gitlabApiToken string
	gitlabUrl      string
)

func NewJobTokenRootCmd() *cobra.Command {
	jobTokenCmd := &cobra.Command{
		Use:   "jobToken",
		Short: "Job token related commands",
		Long:  "Commands to handle job tokens https://docs.gitlab.com/ci/jobs/ci_job_token/#job-token-access",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			rootCmd := cmd.Root()
			if rootCmd != nil && rootCmd.PersistentPreRun != nil && rootCmd != cmd {
				rootCmd.PersistentPreRun(rootCmd, args)
			}

			if err := config.AutoBindFlags(cmd, map[string]string{
				"gitlab": "gitlab.url",
				"token":  "gitlab.token",
			}); err != nil {
				log.Fatal().Err(err).Msg("Failed to bind command flags to configuration keys")
			}

			if err := config.RequireConfigKeys("gitlab.url", "gitlab.token"); err != nil {
				log.Fatal().Err(err).Msg("required configuration missing")
			}

			gitlabApiToken := config.GetString("gitlab.token")
			if !strings.HasPrefix(gitlabApiToken, "glcbt-") {
				log.Fatal().Msg("Only CI job tokens (glcbt-*) are allowed for jobToken commands")
			}

			return nil
		},
	}

	jobTokenCmd.PersistentFlags().StringVarP(&gitlabUrl, "gitlab", "g", "", "GitLab instance URL")
	jobTokenCmd.PersistentFlags().StringVarP(&gitlabApiToken, "token", "t", "", "GitLab CI Job Token")

	jobTokenCmd.AddCommand(exploit.NewExploitCmd())

	return jobTokenCmd
}
