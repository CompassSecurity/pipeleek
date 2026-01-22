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
		Short: "Artipacked auditing commands",
		Long:  "Commands to audit for artipacked misconfiguration in container builds: when Dockerfiles copy secrets during build and leave them in published images.",
	}

	containerCmd.AddCommand(NewArtipackedCmd())

	return containerCmd
}

func NewArtipackedCmd() *cobra.Command {
	artipackedCmd := &cobra.Command{
		Use:   "artipacked [no options!]",
		Short: "Audit for artipacked misconfiguration (secrets in container images)",
		Long:  "Scan GitLab projects for artipacked misconfiguration: dangerous container build patterns that leak secrets like COPY . /path without .dockerignore",
		Run: func(cmd *cobra.Command, args []string) {
			if err := config.AutoBindFlags(cmd, map[string]string{
				"gitlab":             "gitlab.url",
				"token":              "gitlab.token",
				"owned":              "gitlab.container.artipacked.owned",
				"member":             "gitlab.container.artipacked.member",
				"repo":               "gitlab.container.artipacked.repo",
				"namespace":          "gitlab.container.artipacked.namespace",
				"search":             "gitlab.container.artipacked.search",
				"page":               "gitlab.container.artipacked.page",
				"order-by":           "gitlab.container.artipacked.order_by",
				"dangerous-patterns": "gitlab.container.artipacked.dangerous_patterns",
			}); err != nil {
				log.Fatal().Err(err).Msg("Failed to bind command flags to configuration keys")
			}

			gitlabUrl := config.GetString("gitlab.url")
			gitlabApiToken := config.GetString("gitlab.token")

			if err := config.RequireConfigKeys("gitlab.url", "gitlab.token"); err != nil {
				log.Fatal().Err(err).Msg("required configuration missing")
			}

			owned = config.GetBool("gitlab.container.artipacked.owned")
			member = config.GetBool("gitlab.container.artipacked.member")
			repository = config.GetString("gitlab.container.artipacked.repo")
			namespace = config.GetString("gitlab.container.artipacked.namespace")
			projectSearchQuery = config.GetString("gitlab.container.artipacked.search")
			page = config.GetInt("gitlab.container.artipacked.page")
			orderBy = config.GetString("gitlab.container.artipacked.order_by")

			Scan(gitlabUrl, gitlabApiToken)
		},
	}

	artipackedCmd.PersistentFlags().BoolVarP(&owned, "owned", "o", false, "Scan user owned projects only")
	artipackedCmd.PersistentFlags().BoolVarP(&member, "member", "m", false, "Scan projects the user is member of")
	artipackedCmd.Flags().StringVarP(&repository, "repo", "r", "", "Repository to scan (if not set, all projects will be scanned)")
	artipackedCmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Namespace to scan")
	artipackedCmd.Flags().StringVarP(&projectSearchQuery, "search", "s", "", "Query string for searching projects")
	artipackedCmd.Flags().IntVarP(&page, "page", "p", 1, "Page number to start fetching projects from (default 1, fetch all pages)")
	artipackedCmd.Flags().StringVar(&orderBy, "order-by", "last_activity_at", "Order projects by: id, name, path, created_at, updated_at, star_count, last_activity_at, or similarity")

	return artipackedCmd
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
