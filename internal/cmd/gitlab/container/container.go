package container

import (
	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgcontainer "github.com/CompassSecurity/pipeleek/pkg/gitlab/container"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

var (
	owned              bool
	member             bool
	projectSearchQuery string
	page               int
	repository         string
	namespace          string
	orderBy            string
	dangerousPatterns  string
)

func NewContainerScanCmd() *cobra.Command {
	containerCmd := &cobra.Command{
		Use:   "container",
		Short: "Container image scanning commands",
		Long:  "Commands to scan for dangerous container image build patterns in GitLab projects.",
	}

	containerCmd.AddCommand(NewScanCmd())

	return containerCmd
}

func NewScanCmd() *cobra.Command {
	scanCmd := &cobra.Command{
		Use:   "scan [no options!]",
		Short: "Scan for dangerous container image build patterns",
		Long:  "Scan GitLab projects for dangerous container image build patterns like COPY . /path",
		Run: func(cmd *cobra.Command, args []string) {
			if err := config.AutoBindFlags(cmd, map[string]string{
				"gitlab":             "gitlab.url",
				"token":              "gitlab.token",
				"owned":              "gitlab.container.scan.owned",
				"member":             "gitlab.container.scan.member",
				"repo":               "gitlab.container.scan.repo",
				"namespace":          "gitlab.container.scan.namespace",
				"search":             "gitlab.container.scan.search",
				"page":               "gitlab.container.scan.page",
				"order-by":           "gitlab.container.scan.order_by",
				"dangerous-patterns": "gitlab.container.scan.dangerous_patterns",
			}); err != nil {
				log.Fatal().Err(err).Msg("Failed to bind command flags to configuration keys")
			}

			gitlabUrl := config.GetString("gitlab.url")
			gitlabApiToken := config.GetString("gitlab.token")

			if err := config.RequireConfigKeys("gitlab.url", "gitlab.token"); err != nil {
				log.Fatal().Err(err).Msg("required configuration missing")
			}

			owned = config.GetBool("gitlab.container.scan.owned")
			member = config.GetBool("gitlab.container.scan.member")
			repository = config.GetString("gitlab.container.scan.repo")
			namespace = config.GetString("gitlab.container.scan.namespace")
			projectSearchQuery = config.GetString("gitlab.container.scan.search")
			page = config.GetInt("gitlab.container.scan.page")
			orderBy = config.GetString("gitlab.container.scan.order_by")

			Scan(gitlabUrl, gitlabApiToken)
		},
	}

	scanCmd.PersistentFlags().BoolVarP(&owned, "owned", "o", false, "Scan user owned projects only")
	scanCmd.PersistentFlags().BoolVarP(&member, "member", "m", false, "Scan projects the user is member of")
	scanCmd.Flags().StringVarP(&repository, "repo", "r", "", "Repository to scan (if not set, all projects will be scanned)")
	scanCmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Namespace to scan")
	scanCmd.Flags().StringVarP(&projectSearchQuery, "search", "s", "", "Query string for searching projects")
	scanCmd.Flags().IntVarP(&page, "page", "p", 1, "Page number to start fetching projects from (default 1, fetch all pages)")
	scanCmd.Flags().StringVar(&orderBy, "order-by", "last_activity_at", "Order projects by: id, name, path, created_at, updated_at, star_count, last_activity_at, or similarity")

	return scanCmd
}

func Scan(gitlabUrl, gitlabApiToken string) {
	opts := pkgcontainer.ScanOptions{
		GitlabUrl:          gitlabUrl,
		GitlabApiToken:     gitlabApiToken,
		Owned:              owned,
		Member:             member,
		ProjectSearchQuery: projectSearchQuery,
		Page:               page,
		Repository:         repository,
		Namespace:          namespace,
		OrderBy:            orderBy,
		DangerousPatterns:  dangerousPatterns,
		MinAccessLevel:     int(gitlab.GuestPermissions),
	}

	pkgcontainer.RunScan(opts)
}
