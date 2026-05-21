package register

import (
	"github.com/CompassSecurity/pipeleek/pkg/config"
	"github.com/CompassSecurity/pipeleek/pkg/gitlab/util"
	"github.com/spf13/cobra"
)

var flagBindings = map[string]string{
	"url": "gitlab.url",
	"username": "gitlab.register.username",
	"password": "gitlab.register.password",
	"email":    "gitlab.register.email",
}

func NewRegisterCmd() *cobra.Command {
	registerCmd := &cobra.Command{
		Use:     "register",
		Short:   "Register a new user to a Gitlab instance",
		Long:    "Register a new user to a Gitlab instance that allows self-registration. This command is best effort and might not work.",
		Example: `pipeleek gl register --url https://gitlab.mydomain.com --username newuser --password newpassword --email newuser@example.com`,
		Run: func(cmd *cobra.Command, args []string) {
			config.NewCommandSetup(cmd).
				WithFlagBindings(flagBindings).
				RequireKeys("gitlab.url", "gitlab.register.username", "gitlab.register.password", "gitlab.register.email").
				AddValidator(func() error { return config.ValidateURL(config.GetString("gitlab.url"), "GitLab URL") }).
				MustBind()

			gitlabUrl := config.GetString("gitlab.url")
			username := config.GetString("gitlab.register.username")
			password := config.GetString("gitlab.register.password")
			email := config.GetString("gitlab.register.email")

			util.RegisterNewAccount(gitlabUrl, username, password, email)
		},
	}
	registerCmd.Flags().StringP("url", "u", "", "GitLab instance URL")
	registerCmd.Flags().String("username", "", "Username")
	registerCmd.Flags().String("password", "", "Password")
	registerCmd.Flags().String("email", "", "Email Address")

	return registerCmd
}
