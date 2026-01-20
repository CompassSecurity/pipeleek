package container

import (
	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgcontainer "github.com/CompassSecurity/pipeleek/pkg/github/container"
	pkgscan "github.com/CompassSecurity/pipeleek/pkg/github/scan"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	owned              bool
	member             bool
	projectSearchQuery string
	page               int
	repository         string
	organization       string
	orderBy            string
	dangerousPatterns  string
)

func NewContainerScanCmd() *cobra.Command {
	containerCmd := &cobra.Command{
		Use:   "container",
		Short: "Container image scanning commands",
		Long:  "Commands to scan for dangerous container image build patterns in GitHub repositories.",
	}

	containerCmd.AddCommand(NewScanCmd())

	return containerCmd
}

func NewScanCmd() *cobra.Command {
	scanCmd := &cobra.Command{
		Use:   "scan [no options!]",
		Short: "Scan for dangerous container image build patterns",
		Long:  "Scan GitHub repositories for dangerous container image build patterns like COPY . /path",
		Run: func(cmd *cobra.Command, args []string) {
			if err := config.AutoBindFlags(cmd, map[string]string{
				"github":             "github.url",
				"token":              "github.token",
				"owned":              "github.container.scan.owned",
				"member":             "github.container.scan.member",
				"repo":               "github.container.scan.repo",
				"organization":       "github.container.scan.organization",
				"search":             "github.container.scan.search",
				"page":               "github.container.scan.page",
				"order-by":           "github.container.scan.order_by",
				"dangerous-patterns": "github.container.scan.dangerous_patterns",
			}); err != nil {
				log.Fatal().Err(err).Msg("Failed to bind command flags to configuration keys")
			}

			githubUrl := config.GetString("github.url")
			githubApiToken := config.GetString("github.token")

			if err := config.RequireConfigKeys("github.url", "github.token"); err != nil {
				log.Fatal().Err(err).Msg("required configuration missing")
			}

			owned = config.GetBool("github.container.scan.owned")
			member = config.GetBool("github.container.scan.member")
			repository = config.GetString("github.container.scan.repo")
			organization = config.GetString("github.container.scan.organization")
			projectSearchQuery = config.GetString("github.container.scan.search")
			page = config.GetInt("github.container.scan.page")
			orderBy = config.GetString("github.container.scan.order_by")

			Scan(githubUrl, githubApiToken)
		},
	}

	scanCmd.PersistentFlags().BoolVarP(&owned, "owned", "o", false, "Scan user owned repositories only")
	scanCmd.PersistentFlags().BoolVarP(&member, "member", "m", false, "Scan repositories the user is member of")
	scanCmd.Flags().StringVarP(&repository, "repo", "r", "", "Repository to scan (if not set, all repositories will be scanned)")
	scanCmd.Flags().StringVarP(&organization, "organization", "n", "", "Organization to scan")
	scanCmd.Flags().StringVarP(&projectSearchQuery, "search", "s", "", "Query string for searching repositories")
	scanCmd.Flags().IntVarP(&page, "page", "p", 1, "Page number to start fetching repositories from (default 1)")
	scanCmd.Flags().StringVar(&orderBy, "order-by", "updated", "Order repositories by: stars, forks, updated")

	return scanCmd
}

func Scan(githubUrl, githubApiToken string) {
	client := pkgscan.SetupClient(githubApiToken, githubUrl)

	opts := pkgcontainer.ScanOptions{
		GitHubUrl:          githubUrl,
		GitHubApiToken:     githubApiToken,
		Owned:              owned,
		Member:             member,
		ProjectSearchQuery: projectSearchQuery,
		Page:               page,
		Repository:         repository,
		Organization:       organization,
		OrderBy:            orderBy,
		DangerousPatterns:  dangerousPatterns,
	}

	pkgcontainer.RunScan(opts, client)
}
