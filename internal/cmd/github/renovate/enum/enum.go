package enum

import (
	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgrenovate "github.com/CompassSecurity/pipeleek/pkg/github/renovate/enum"
	pkgscan "github.com/CompassSecurity/pipeleek/pkg/github/scan"
	"github.com/spf13/cobra"
)

// EnumOptions represents all configuration options for the enum command
type EnumOptions struct {
	URL                         string
	Token                       string
	Owned                       bool
	Member                      bool
	SearchQuery                 string
	Fast                        bool
	Dump                        bool
	Page                        int
	Repository                  string
	Organization                string
	OrderBy                     string
	ExtendRenovateConfigService string
}

var flagBindings = map[string]string{
	"url":                            "github.url",
	"token":                          "github.token",
	"owned":                          "github.renovate.enum.owned",
	"member":                         "github.renovate.enum.member",
	"repo":                           "github.renovate.enum.repo",
	"org":                            "github.renovate.enum.org",
	"search":                         "github.renovate.enum.search",
	"fast":                           "github.renovate.enum.fast",
	"dump":                           "github.renovate.enum.dump",
	"page":                           "github.renovate.enum.page",
	"order-by":                       "github.renovate.enum.order_by",
	"extend-renovate-config-service": "github.renovate.enum.extend_renovate_config_service",
}

// RunEnumerate handles the enum command execution
func RunEnumerate(cmd *cobra.Command, args []string) {
	config.NewCommandSetup(cmd).
		WithFlagBindings(flagBindings).
		RequireKeys("github.token").
		MustBind()

	opts := EnumOptions{
		URL:                         config.GetString("github.url"),
		Token:                       config.GetString("github.token"),
		Owned:                       config.GetBool("github.renovate.enum.owned"),
		Member:                      config.GetBool("github.renovate.enum.member"),
		Repository:                  config.GetString("github.renovate.enum.repo"),
		Organization:                config.GetString("github.renovate.enum.org"),
		SearchQuery:                 config.GetString("github.renovate.enum.search"),
		Fast:                        config.GetBool("github.renovate.enum.fast"),
		Dump:                        config.GetBool("github.renovate.enum.dump"),
		Page:                        config.GetInt("github.renovate.enum.page"),
		OrderBy:                     config.GetString("github.renovate.enum.order_by"),
		ExtendRenovateConfigService: config.GetString("github.renovate.enum.extend_renovate_config_service"),
	}

	enumerate(opts)
}

func NewEnumCmd() *cobra.Command {
	enumCmd := &cobra.Command{
		Use:   "enum [no options!]",
		Short: "Enumerate Renovate configurations",
		Long:  "Enumerate GitHub repositories for Renovate bot configurations. Identifies repositories with Renovate workflows, config files, autodiscovery settings, and self-hosted configurations.",
		Example: `
# Enumerate all owned repositories
pipeleek gh renovate enum --url https://api.github.com --token ghp_xxxxx --owned

# Enumerate all public repositories
pipeleek gh renovate enum --url https://api.github.com --token ghp_xxxxx

# Enumerate specific organization
pipeleek gh renovate enum --url https://api.github.com --token ghp_xxxxx --org mycompany

# Enumerate with config file dump
pipeleek gh renovate enum --url https://api.github.com --token ghp_xxxxx --owned --dump

# Fast mode (skip config file detection)
pipeleek gh renovate enum --url https://api.github.com --token ghp_xxxxx --org myorg --fast

# Enumerate specific repository
pipeleek gh renovate enum --url https://api.github.com --token ghp_xxxxx --repo owner/repo
`,
		Run: RunEnumerate,
	}

	var owned, member, fast, dump bool
	var searchQuery, repository, organization, orderBy, extendRenovateConfigService string
	var page int

	enumCmd.PersistentFlags().BoolVarP(&owned, "owned", "o", false, "Scan user owned repositories only")
	enumCmd.PersistentFlags().BoolVarP(&member, "member", "m", false, "Scan repositories the user is member of")
	enumCmd.Flags().StringVarP(&repository, "repo", "r", "", "Repository to scan for Renovate configuration in format owner/repo (if not set, all repositories will be scanned)")
	enumCmd.Flags().StringVar(&organization, "org", "", "Organization to scan")
	enumCmd.Flags().StringVarP(&searchQuery, "search", "s", "", "Query string for searching repositories")
	enumCmd.Flags().BoolVarP(&fast, "fast", "f", false, "Fast mode - skip renovate config file detection, only check workflow files for renovate bot job (default false)")
	enumCmd.Flags().BoolVarP(&dump, "dump", "d", false, "Dump mode - save all config files to renovate-enum-out folder (default false)")
	enumCmd.Flags().IntVarP(&page, "page", "p", 1, "Page number to start fetching repositories from (default 1, fetch all pages)")
	enumCmd.Flags().StringVar(&orderBy, "order-by", "created", "Order repositories by: created, updated, pushed, or full_name")
	enumCmd.Flags().StringVar(&extendRenovateConfigService, "extend-renovate-config-service", "", "Base URL of the resolver service e.g. http://localhost:3000 (docker run -ti -p 3000:3000 jfrcomp/renovate-config-resolver:latest). Renovate configs can be extended by shareable preset, resolving them makes enumeration more accurate.")

	enumCmd.MarkFlagsMutuallyExclusive("owned", "member", "repo", "org", "search")

	return enumCmd
}

// enumerate contains the business logic and is now testable in isolation
func enumerate(opts EnumOptions) {
	client := pkgscan.SetupClient(opts.Token, opts.URL)

	pkgOpts := pkgrenovate.EnumOptions{
		GitHubURL:                   opts.URL,
		GitHubToken:                 opts.Token,
		Owned:                       opts.Owned,
		Member:                      opts.Member,
		SearchQuery:                 opts.SearchQuery,
		Fast:                        opts.Fast,
		Dump:                        opts.Dump,
		Page:                        opts.Page,
		Repository:                  opts.Repository,
		Organization:                opts.Organization,
		OrderBy:                     opts.OrderBy,
		ExtendRenovateConfigService: opts.ExtendRenovateConfigService,
	}

	pkgrenovate.RunEnumerate(client, pkgOpts)
}
