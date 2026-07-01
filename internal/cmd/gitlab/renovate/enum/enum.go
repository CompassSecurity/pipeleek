package enum

import (
	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgrenovate "github.com/CompassSecurity/pipeleek/pkg/gitlab/renovate/enum"
	"github.com/spf13/cobra"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// EnumOptions represents all configuration options for the enum command
type EnumOptions struct {
	URL                         string
	Token                       string
	Owned                       bool
	Member                      bool
	Repository                  string
	Namespace                   string
	SearchQuery                 string
	Fast                        bool
	Dump                        bool
	Page                        int
	OrderBy                     string
	ExtendRenovateConfigService string
}

var flagBindings = map[string]string{
	"url":                            "gitlab.url",
	"token":                          "gitlab.token",
	"owned":                          "gitlab.renovate.enum.owned",
	"member":                         "gitlab.renovate.enum.member",
	"repo":                           "gitlab.renovate.enum.repo",
	"namespace":                      "gitlab.renovate.enum.namespace",
	"search":                         "gitlab.renovate.enum.search",
	"fast":                           "gitlab.renovate.enum.fast",
	"dump":                           "gitlab.renovate.enum.dump",
	"page":                           "gitlab.renovate.enum.page",
	"order-by":                       "gitlab.renovate.enum.order_by",
	"extend-renovate-config-service": "gitlab.renovate.enum.extend_renovate_config_service",
}

// RunEnumerate handles the enum command execution
func RunEnumerate(cmd *cobra.Command, args []string) {
	config.NewCommandSetup(cmd).
		WithFlagBindings(flagBindings).
		RequireKeys("gitlab.url", "gitlab.token").
		MustBind()

	opts := EnumOptions{
		URL:                         config.GetString("gitlab.url"),
		Token:                       config.GetString("gitlab.token"),
		Owned:                       config.GetBool("gitlab.renovate.enum.owned"),
		Member:                      config.GetBool("gitlab.renovate.enum.member"),
		Repository:                  config.GetString("gitlab.renovate.enum.repo"),
		Namespace:                   config.GetString("gitlab.renovate.enum.namespace"),
		SearchQuery:                 config.GetString("gitlab.renovate.enum.search"),
		Fast:                        config.GetBool("gitlab.renovate.enum.fast"),
		Dump:                        config.GetBool("gitlab.renovate.enum.dump"),
		Page:                        config.GetInt("gitlab.renovate.enum.page"),
		OrderBy:                     config.GetString("gitlab.renovate.enum.order_by"),
		ExtendRenovateConfigService: config.GetString("gitlab.renovate.enum.extend_renovate_config_service"),
	}

	enumerate(opts)
}

func NewEnumCmd() *cobra.Command {
	enumCmd := &cobra.Command{
		Use:   "enum [no options!]",
		Short: "Enumerate Renovate configurations",
		Run:   RunEnumerate,
	}

	var owned, member, fast, dump bool
	var projectSearchQuery, repository, namespace, orderBy, extendRenovateConfigService string
	var page int

	enumCmd.PersistentFlags().BoolVarP(&owned, "owned", "o", false, "Scan user owned projects only")
	enumCmd.PersistentFlags().BoolVarP(&member, "member", "m", false, "Scan projects the user is member of")
	enumCmd.Flags().StringVarP(&repository, "repo", "r", "", "Repository to scan for Renovate configuration (if not set, all repositories will be scanned)")
	enumCmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Namespace to scan")
	enumCmd.Flags().StringVarP(&projectSearchQuery, "search", "s", "", "Query string for searching projects")
	enumCmd.Flags().BoolVarP(&fast, "fast", "f", false, "Fast mode - skip renovate config file detection, only check CIDC yml for renovate bot job (default false)")
	enumCmd.Flags().BoolVarP(&dump, "dump", "d", false, "Dump mode - save all config files to renovate-enum-out folder (default false)")
	enumCmd.Flags().IntVar(&page, "page", 1, "Page number to start fetching projects from (default 1, fetch all pages)")
	enumCmd.Flags().StringVar(&orderBy, "order-by", "created_at", "Order projects by: id, name, path, created_at, updated_at, star_count, last_activity_at, or similarity")
	enumCmd.Flags().StringVar(&extendRenovateConfigService, "extend-renovate-config-service", "", "Base URL of the resolver service e.g.  http://localhost:3000 (docker run -ti -p 3000:3000 jfrcomp/renovate-config-resolver:latest). Renovate configs can be extended by shareable preset, resolving them makes enumeration more accurate.")

	return enumCmd
}

// enumerate contains the business logic and is now testable in isolation
func enumerate(opts EnumOptions) {
	pkgOpts := pkgrenovate.EnumOptions{
		GitlabUrl:                   opts.URL,
		GitlabApiToken:              opts.Token,
		Owned:                       opts.Owned,
		Member:                      opts.Member,
		ProjectSearchQuery:          opts.SearchQuery,
		Fast:                        opts.Fast,
		Dump:                        opts.Dump,
		Page:                        opts.Page,
		Repository:                  opts.Repository,
		Namespace:                   opts.Namespace,
		OrderBy:                     opts.OrderBy,
		ExtendRenovateConfigService: opts.ExtendRenovateConfigService,
		MinAccessLevel:              int(gitlab.GuestPermissions),
	}

	pkgrenovate.RunEnumerate(pkgOpts)
}
