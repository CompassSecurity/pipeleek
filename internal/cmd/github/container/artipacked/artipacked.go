package artipacked

import (
	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgcontainer "github.com/CompassSecurity/pipeleek/pkg/github/container/artipacked"
	pkgscan "github.com/CompassSecurity/pipeleek/pkg/github/scan"
	"github.com/spf13/cobra"
)

type artipackedOptions struct {
	URL                string
	Token              string
	Owned              bool
	Member             bool
	Public             bool
	Repository         string
	Organization       string
	ProjectSearchQuery string
	Page               int
	OrderBy            string
	DangerousPatterns  string
}

var flagBindings = map[string]string{
	"url":          "github.url",
	"token":        "github.token",
	"owned":        "github.container.artipacked.owned",
	"member":       "github.container.artipacked.member",
	"public":       "github.container.artipacked.public",
	"repo":         "github.container.artipacked.repo",
	"organization": "github.container.artipacked.organization",
	"search":       "github.container.artipacked.search",
	"page":         "github.container.artipacked.page",
	"order-by":     "github.container.artipacked.order_by",
}

func RunArtipacked(cmd *cobra.Command, args []string) {
	config.NewCommandSetup(cmd).
		WithFlagBindings(flagBindings).
		RequireKeys("github.url", "github.token").
		MustBind()

	opts := artipackedOptions{
		URL:                config.GetString("github.url"),
		Token:              config.GetString("github.token"),
		Owned:              config.GetBool("github.container.artipacked.owned"),
		Member:             config.GetBool("github.container.artipacked.member"),
		Public:             config.GetBool("github.container.artipacked.public"),
		Repository:         config.GetString("github.container.artipacked.repo"),
		Organization:       config.GetString("github.container.artipacked.organization"),
		ProjectSearchQuery: config.GetString("github.container.artipacked.search"),
		Page:               config.GetInt("github.container.artipacked.page"),
		OrderBy:            config.GetString("github.container.artipacked.order_by"),
	}

	scan(opts)
}

func NewArtipackedCmd() *cobra.Command {
	artipackedCmd := &cobra.Command{
		Use:   "artipacked",
		Short: "Audit for artipacked misconfiguration (secrets in container images)",
		Long:  "Scan for dangerous container build patterns that leak secrets like COPY . /path without .dockerignore",
		Run:   RunArtipacked,
	}

	var owned, member, public bool
	var repository, organization, projectSearchQuery, orderBy string
	var page int

	artipackedCmd.PersistentFlags().BoolVarP(&owned, "owned", "o", false, "Scan user owned repositories only")
	artipackedCmd.PersistentFlags().BoolVarP(&member, "member", "m", false, "Scan repositories the user is member of")
	artipackedCmd.PersistentFlags().BoolVar(&public, "public", false, "Scan public repositories only")
	artipackedCmd.Flags().StringP("url", "u", "", "GitHub instance URL")
	artipackedCmd.Flags().StringP("token", "t", "", "GitHub API token")
	artipackedCmd.Flags().StringVarP(&repository, "repo", "r", "", "Repository to scan (if not set, all repositories will be scanned)")
	artipackedCmd.Flags().StringVarP(&organization, "organization", "n", "", "Organization to scan")
	artipackedCmd.Flags().StringVarP(&projectSearchQuery, "search", "s", "", "Query string for searching repositories")
	artipackedCmd.Flags().IntVarP(&page, "page", "p", 1, "Page number to start fetching repositories from (default 1)")
	artipackedCmd.Flags().StringVar(&orderBy, "order-by", "updated", "Order repositories by: stars, forks, updated")

	return artipackedCmd
}

func scan(opts artipackedOptions) {
	client := pkgscan.SetupClient(opts.Token, opts.URL)

	pkgcontainer.RunScan(pkgcontainer.ScanOptions{
		GitHubUrl:          opts.URL,
		GitHubApiToken:     opts.Token,
		Owned:              opts.Owned,
		Member:             opts.Member,
		Public:             opts.Public,
		ProjectSearchQuery: opts.ProjectSearchQuery,
		Page:               opts.Page,
		Repository:         opts.Repository,
		Organization:       opts.Organization,
		OrderBy:            opts.OrderBy,
		DangerousPatterns:  opts.DangerousPatterns,
	}, client)
}
