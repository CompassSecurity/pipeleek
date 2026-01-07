package register

import (
	"github.com/CompassSecurity/pipeleek/pkg/config"
	"github.com/CompassSecurity/pipeleek/pkg/gitlab/util"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func NewRegisterCmd() *cobra.Command {
	registerCmd := &cobra.Command{
		Use:     "register",
		Short:   "Register a new user to a Gitlab instance",
		Long:    "Register a new user to a Gitlab instance that allows self-registration. This command is best effort and might not work.",
		Example: `pipeleek gl register --gitlab https://gitlab.mydomain.com --username newuser --password newpassword --email newuser@example.com`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := config.BindCommandFlags(cmd, "gitlab.register", map[string]string{
				"gitlab": "gitlab.url",
			}); err != nil {
				log.Fatal().Err(err).Msg("Failed to bind flags")
			}

			if err := config.RequireConfigKeys("gitlab.url", "gitlab.register.username", "gitlab.register.password", "gitlab.register.email"); err != nil {
				log.Fatal().Err(err).Msg("required configuration missing")
			}

			gitlabUrl := config.GetString("gitlab.url")
			username := config.GetString("gitlab.register.username")
			password := config.GetString("gitlab.register.password")
			email := config.GetString("gitlab.register.email")

			if err := config.ValidateURL(gitlabUrl, "GitLab URL"); err != nil {
				log.Fatal().Err(err).Msg("Invalid GitLab URL")
			}

			util.RegisterNewAccount(gitlabUrl, username, password, email)
		},
	}
	registerCmd.Flags().String("gitlab", "", "GitLab instance URL")
	registerCmd.Flags().String("username", "", "Username")
	registerCmd.Flags().String("password", "", "Password")
	registerCmd.Flags().String("email", "", "Email Address")

	return registerCmd
}
