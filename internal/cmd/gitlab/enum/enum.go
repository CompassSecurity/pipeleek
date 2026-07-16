package enum

import (
	"fmt"
	"strings"

	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgenum "github.com/CompassSecurity/pipeleek/pkg/gitlab/enum"
	gitlabutil "github.com/CompassSecurity/pipeleek/pkg/gitlab/util"
	"github.com/CompassSecurity/pipeleek/pkg/logging"
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
	"users-concurrency": "gitlab.enum.users_concurrency",
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
	enumCmd.Flags().Int("users-concurrency", 2, "Number of concurrent member-fetch workers used by --users")

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
		AddValidator(func() error {
			usersConcurrency := config.GetInt("gitlab.enum.users_concurrency")
			if usersConcurrency < 1 {
				return fmt.Errorf("users-concurrency must be >= 1")
			}

			return nil
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

	logging.RegisterStatusHook(pkgenum.StatusHook)

	pkgenum.RunEnumWithOptions(
		config.GetString("gitlab.url"),
		config.GetString("gitlab.token"),
		int(level),
		pkgenum.ExportOptions{
			HTMLReportPath: config.GetString("gitlab.enum.report_html"),
			EnumerateUsers: config.GetBool("gitlab.enum.users"),
			UsersConcurrency: config.GetInt("gitlab.enum.users_concurrency"),
		},
	)
}
