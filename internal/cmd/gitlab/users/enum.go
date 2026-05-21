package users

import (
	"strings"

	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgusers "github.com/CompassSecurity/pipeleek/pkg/gitlab/users"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var flagBindings = map[string]string{
	"url":   "gitlab.url",
	"token": "gitlab.token",
}

func NewEnumCmd() *cobra.Command {
	return newEnumCmd(true)
}

func NewUnauthenticatedEnumCmd() *cobra.Command {
	return newEnumCmd(false)
}

func newEnumCmd(includeTokenFlag bool) *cobra.Command {
	enumCmd := &cobra.Command{
		Use:     "enum",
		Short:   "Enumerate GitLab users",
		Long:    "Enumerate GitLab users visible via the GitLab users API.",
		Example: unauthenticatedEnumExample(includeTokenFlag),
		Run:     Enum,
	}
	enumCmd.Flags().StringP("url", "u", "", "GitLab instance URL")
	if includeTokenFlag {
		enumCmd.Flags().StringP("token", "t", "", "GitLab API Token")
	}

	return enumCmd
}

func unauthenticatedEnumExample(includeTokenFlag bool) string {
	if includeTokenFlag {
		return `pipeleek gl users enum --url https://gitlab.example.com --token glpat-xxxxxxxxxxx`
	}

	return `pipeleek gluna users enum --url https://gitlab.example.com`
}

func Enum(cmd *cobra.Command, args []string) {
	config.NewCommandSetup(cmd).
		WithFlagBindings(flagBindings).
		RequireKeys("gitlab.url").
		AddValidator(func() error { return config.ValidateURL(config.GetString("gitlab.url"), "GitLab URL") }).
		MustBind()

	gitlabURL := config.GetString("gitlab.url")
	gitlabAPIToken := config.GetString("gitlab.token")

	// gluna commands are intentionally unauthenticated for users enum.
	if isSubcommandOf(cmd, "gluna") {
		if strings.TrimSpace(gitlabAPIToken) != "" {
			log.Warn().Msg("Ignoring provided GitLab API token for gluna users enum; command runs unauthenticated")
		}
		gitlabAPIToken = ""
	}

	if gitlabAPIToken != "" {
		if err := config.ValidateToken(gitlabAPIToken, "GitLab API Token"); err != nil {
			log.Fatal().Err(err).Msg("Invalid GitLab API Token")
		}
	}

	pkgusers.RunEnum(gitlabURL, gitlabAPIToken)
}

func isSubcommandOf(cmd *cobra.Command, rootName string) bool {
	for current := cmd; current != nil; current = current.Parent() {
		if current.Name() == rootName {
			return true
		}
	}
	return false
}
