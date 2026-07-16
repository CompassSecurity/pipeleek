package enum

import (
	"strings"

	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgenum "github.com/CompassSecurity/pipeleek/pkg/gitlab/enum"
	gitlabutil "github.com/CompassSecurity/pipeleek/pkg/gitlab/util"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
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
		Example: `pipeleek gl enum --token glpat-xxxxxxxxxxx --url https://gitlab.mydomain.com --level minimal`,
		Run:     Enum,
	}
	enumCmd.Flags().StringP("url", "u", "", "GitLab instance URL")
	enumCmd.Flags().StringP("token", "t", "", "GitLab API Token")
	enumCmd.Flags().String("level", "", gitlabutil.AccessLevelHelpText())
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
		AddValidator(func() error {
			levelRaw := strings.TrimSpace(config.GetString("gitlab.enum.level"))
			if levelRaw == "" {
				return nil
			}

			_, err := gitlabutil.ParseAccessLevel(levelRaw)
			return err
		}).
		MustBind()

	level := -1
	levelRaw := strings.TrimSpace(config.GetString("gitlab.enum.level"))
	if levelRaw != "" {
		parsedLevel, err := gitlabutil.ParseAccessLevel(levelRaw)
		if err != nil {
			log.Fatal().Err(err).Str("level", config.GetString("gitlab.enum.level")).Msg("Invalid GitLab access level")
		}
		level = int(parsedLevel)
	}

	pkgenum.RunEnumWithOptions(
		config.GetString("gitlab.url"),
		config.GetString("gitlab.token"),
		int(level),
		pkgenum.ExportOptions{
			HTMLReportPath: config.GetString("gitlab.enum.report_html"),
			EnumerateUsers: config.GetBool("gitlab.enum.users"),
		},
	)
}
