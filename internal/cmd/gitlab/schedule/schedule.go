package schedule

import (
	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgschedule "github.com/CompassSecurity/pipeleek/pkg/gitlab/schedule"
	"github.com/spf13/cobra"
)

func NewScheduleCmd() *cobra.Command {
	scheduleCmd := &cobra.Command{
		Use:     "schedule",
		Short:   "Enumerate scheduled pipelines and dump their variables",
		Long:    "Fetch and print all scheduled pipelines and their variables for projects your token has access to.",
		Example: `pipeleek gl schedule --token glpat-xxxxxxxxxxx --url https://gitlab.mydomain.com`,
		Run:     FetchSchedules,
	}
	scheduleCmd.Flags().StringP("url", "u", "", "GitLab instance URL")
	scheduleCmd.Flags().StringP("token", "t", "", "GitLab API Token")

	return scheduleCmd
}

func FetchSchedules(cmd *cobra.Command, args []string) {
	// Auto-generate bindings from flag definitions with optional overrides
	bindings := config.BindingsFromFlags(cmd, "gitlab", "schedule", map[string]string{
		"url":   "gitlab.url",
		"token": "gitlab.token",
	})

	config.NewCommandSetup(cmd).
		WithFlagBindings(bindings).
		RequireKeys("gitlab.url", "gitlab.token").
		AddValidator(func() error { return config.ValidateURL(config.GetString("gitlab.url"), "GitLab URL") }).
		AddValidator(func() error { return config.ValidateToken(config.GetString("gitlab.token"), "GitLab API Token") }).
		MustBind()

	pkgschedule.RunFetchSchedules(
		config.GetString("gitlab.url"),
		config.GetString("gitlab.token"),
	)
}
