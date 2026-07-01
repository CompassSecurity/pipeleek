package artipacked

import (
	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgcontainer "github.com/CompassSecurity/pipeleek/pkg/gitlab/container/artipacked"
	"github.com/spf13/cobra"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

type artipackedOptions struct {
	URL                string
	Token              string
	Owned              bool
	Member             bool
	Repository         string
	Namespace          string
	ProjectSearchQuery string
	Page               int
	OrderBy            string
}

var flagBindings = map[string]string{
	"url":       "gitlab.url",
	"token":     "gitlab.token",
	"owned":     "gitlab.container.artipacked.owned",
	"member":    "gitlab.container.artipacked.member",
	"repo":      "gitlab.container.artipacked.repo",
	"namespace": "gitlab.container.artipacked.namespace",
	"search":    "gitlab.container.artipacked.search",
	"page":      "gitlab.container.artipacked.page",
	"order-by":  "gitlab.container.artipacked.order_by",
}

// RunArtipacked handles the artipacked command execution
func RunArtipacked(cmd *cobra.Command, args []string) {
	config.NewCommandSetup(cmd).
		WithFlagBindings(flagBindings).
		RequireKeys("gitlab.url", "gitlab.token").
		MustBind()

	opts := artipackedOptions{
		URL:                config.GetString("gitlab.url"),
		Token:              config.GetString("gitlab.token"),
		Owned:              config.GetBool("gitlab.container.artipacked.owned"),
		Member:             config.GetBool("gitlab.container.artipacked.member"),
		Repository:         config.GetString("gitlab.container.artipacked.repo"),
		Namespace:          config.GetString("gitlab.container.artipacked.namespace"),
		ProjectSearchQuery: config.GetString("gitlab.container.artipacked.search"),
		Page:               config.GetInt("gitlab.container.artipacked.page"),
		OrderBy:            config.GetString("gitlab.container.artipacked.order_by"),
	}

	scan(opts)
}

func NewArtipackedCmd() *cobra.Command {
	var owned, member bool
	var repository, namespace, projectSearchQuery, orderBy string
	var page int

	artipackedCmd := &cobra.Command{
		Use:   "artipacked",
		Short: "Audit for artipacked misconfiguration (secrets in container images)",
		Long:  "Scan for dangerous container build patterns that leak secrets like COPY . /path without .dockerignore",
		Run:   RunArtipacked,
	}

	artipackedCmd.PersistentFlags().BoolVarP(&owned, "owned", "o", false, "Scan user owned projects only")
	artipackedCmd.PersistentFlags().BoolVarP(&member, "member", "m", false, "Scan projects the user is member of")
	artipackedCmd.Flags().StringVarP(&repository, "repo", "r", "", "Repository to scan (if not set, all repositories will be scanned)")
	artipackedCmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Namespace to scan")
	artipackedCmd.Flags().StringVarP(&projectSearchQuery, "search", "s", "", "Query string for searching projects")
	artipackedCmd.Flags().IntVar(&page, "page", 1, "Page number to start fetching projects from (default 1, fetch all pages)")
	artipackedCmd.Flags().StringVar(&orderBy, "order-by", "last_activity_at", "Order projects by: id, name, path, created_at, updated_at, star_count, last_activity_at, or similarity")

	return artipackedCmd
}

func scan(opts artipackedOptions) {
	pkgcontainer.RunScan(pkgcontainer.ScanOptions{
		GitlabUrl:          opts.URL,
		GitlabApiToken:     opts.Token,
		Owned:              opts.Owned,
		Member:             opts.Member,
		ProjectSearchQuery: opts.ProjectSearchQuery,
		Page:               opts.Page,
		Repository:         opts.Repository,
		Namespace:          opts.Namespace,
		OrderBy:            opts.OrderBy,
		MinAccessLevel:     int(gitlab.GuestPermissions),
	})
}
