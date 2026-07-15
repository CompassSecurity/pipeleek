package enum

import (
	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgenum "github.com/CompassSecurity/pipeleek/pkg/gitlab/enum"
	"github.com/spf13/cobra"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// flagBindings maps CLI flags to configuration keys
var flagBindings = map[string]string{
	"url":         "gitlab.url",
	"token":       "gitlab.token",
	"level":       "gitlab.enum.level",
	"report-html": "gitlab.enum.report_html",
	"users":       "gitlab.enum.users",
}

func NewEnumCmd() *cobra.Command {
	enumCmd := &cobra.Command{
		Use:     "enum",
		Short:   "Enumerate access rights of a GitLab access token",
		Long:    "Enumerate access rights of a GitLab access token by listing projects, groups and users the token has access to.",
		Example: `pipeleek gl enum --token glpat-xxxxxxxxxxx --url https://gitlab.mydomain.com --level 20`,
		Run:     Enum,
	}
	enumCmd.Flags().StringP("url", "u", "", "GitLab instance URL")
	enumCmd.Flags().StringP("token", "t", "", "GitLab API Token")
	enumCmd.Flags().Int("level", int(gitlab.GuestPermissions), "Minimum repo access level. See https://docs.gitlab.com/api/access_requests/#valid-access-levels for integer values")
	enumCmd.Flags().String("report-html", "", "Write an HTML visualization report to the given file path")
	enumCmd.Flags().Bool("users", false, "Enumerate members from discovered groups/projects and include them in HTML report")

	return enumCmd
}

func Enum(cmd *cobra.Command, args []string) {
	config.NewCommandSetup(cmd).
		WithFlagBindings(flagBindings).
		RequireKeys("gitlab.url", "gitlab.token").
		AddValidator(func() error { return config.ValidateURL(config.GetString("gitlab.url"), "GitLab URL") }).
		AddValidator(func() error { return config.ValidateToken(config.GetString("gitlab.token"), "GitLab API Token") }).
		MustBind()

	pkgenum.RunEnumWithOptions(
		config.GetString("gitlab.url"),
		config.GetString("gitlab.token"),
		config.GetInt("gitlab.enum.level"),
		pkgenum.ExportOptions{
			HTMLReportPath: config.GetString("gitlab.enum.report_html"),
			EnumerateUsers: config.GetBool("gitlab.enum.users"),
		},
	)
}
