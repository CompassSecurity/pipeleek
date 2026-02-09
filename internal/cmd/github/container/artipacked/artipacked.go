package artipacked

import (
	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgcontainer "github.com/CompassSecurity/pipeleek/pkg/github/container/artipacked"
	pkgscan "github.com/CompassSecurity/pipeleek/pkg/github/scan"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	owned              bool
	member             bool
	public             bool
	projectSearchQuery string
	page               int
	repository         string
	organization       string
	orderBy            string
	dangerousPatterns  string
)

func NewArtipackedCmd() *cobra.Command {
	artipackedCmd := &cobra.Command{
		Use:   "artipacked",
		Short: "Audit for artipacked misconfiguration (secrets in container images)",
		Long:  "Scan for dangerous container build patterns that leak secrets like COPY . /path without .dockerignore",
		Run: func(cmd *cobra.Command, args []string) {
			if err := config.AutoBindFlags(cmd, map[string]string{
				"github":       "github.url",
				"token":        "github.token",
				"owned":        "github.container.artipacked.owned",
				"member":       "github.container.artipacked.member",
				"public":       "github.container.artipacked.public",
				"repo":         "github.container.artipacked.repo",
				"organization": "github.container.artipacked.organization",
				"search":       "github.container.artipacked.search",
				"page":         "github.container.artipacked.page",
				"order-by":     "github.container.artipacked.order_by",
			}); err != nil {
				log.Fatal().Err(err).Msg("Failed to bind command flags to configuration keys")
			}

			githubUrl := config.GetString("github.url")
			githubApiToken := config.GetString("github.token")

			if err := config.RequireConfigKeys("github.url", "github.token"); err != nil {
				log.Fatal().Err(err).Msg("required configuration missing")
			}

			owned = config.GetBool("github.container.artipacked.owned")
			member = config.GetBool("github.container.artipacked.member")
			public = config.GetBool("github.container.artipacked.public")
			repository = config.GetString("github.container.artipacked.repo")
			organization = config.GetString("github.container.artipacked.organization")
			projectSearchQuery = config.GetString("github.container.artipacked.search")
			page = config.GetInt("github.container.artipacked.page")
			orderBy = config.GetString("github.container.artipacked.order_by")

			Scan(githubUrl, githubApiToken)
		},
	}

	artipackedCmd.PersistentFlags().BoolVarP(&owned, "owned", "o", false, "Scan user owned repositories only")
	artipackedCmd.PersistentFlags().BoolVarP(&member, "member", "m", false, "Scan repositories the user is member of")
	artipackedCmd.PersistentFlags().BoolVar(&public, "public", false, "Scan public repositories only")
	artipackedCmd.Flags().StringP("github", "g", "", "GitHub instance URL")
	artipackedCmd.Flags().StringP("token", "t", "", "GitHub API token")
	artipackedCmd.Flags().StringVarP(&repository, "repo", "r", "", "Repository to scan (if not set, all repositories will be scanned)")
	artipackedCmd.Flags().StringVarP(&organization, "organization", "n", "", "Organization to scan")
	artipackedCmd.Flags().StringVarP(&projectSearchQuery, "search", "s", "", "Query string for searching repositories")
	artipackedCmd.Flags().IntVarP(&page, "page", "p", 1, "Page number to start fetching repositories from (default 1)")
	artipackedCmd.Flags().StringVar(&orderBy, "order-by", "updated", "Order repositories by: stars, forks, updated")

	return artipackedCmd
}

func Scan(githubUrl, githubApiToken string) {
	client := pkgscan.SetupClient(githubApiToken, githubUrl)

	opts := pkgcontainer.ScanOptions{
		GitHubUrl:          githubUrl,
		GitHubApiToken:     githubApiToken,
		Owned:              owned,
		Member:             member,
		Public:             public,
		ProjectSearchQuery: projectSearchQuery,
		Page:               page,
		Repository:         repository,
		Organization:       organization,
		OrderBy:            orderBy,
		DangerousPatterns:  dangerousPatterns,
	}

	pkgcontainer.RunScan(opts, client)
}
