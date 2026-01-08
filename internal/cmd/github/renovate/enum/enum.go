package enum

import (
	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgrenovate "github.com/CompassSecurity/pipeleek/pkg/github/renovate/enum"
	pkgscan "github.com/CompassSecurity/pipeleek/pkg/github/scan"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	owned                       bool
	member                      bool
	searchQuery                 string
	fast                        bool
	dump                        bool
	page                        int
	repository                  string
	organization                string
	orderBy                     string
	extendRenovateConfigService string
)

func NewEnumCmd() *cobra.Command {
	enumCmd := &cobra.Command{
		Use:   "enum [no options!]",
		Short: "Enumerate Renovate configurations",
		Long:  "Enumerate GitHub repositories for Renovate bot configurations. Identifies repositories with Renovate workflows, config files, autodiscovery settings, and self-hosted configurations.",
		Example: `
# Enumerate all owned repositories
pipeleek gh renovate enum --github https://api.github.com --token ghp_xxxxx --owned

# Enumerate all public repositories
pipeleek gh renovate enum --github https://api.github.com --token ghp_xxxxx

# Enumerate specific organization
pipeleek gh renovate enum --github https://api.github.com --token ghp_xxxxx --org mycompany

# Enumerate with config file dump
pipeleek gh renovate enum --github https://api.github.com --token ghp_xxxxx --owned --dump

# Fast mode (skip config file detection)
pipeleek gh renovate enum --github https://api.github.com --token ghp_xxxxx --org myorg --fast

# Enumerate specific repository
pipeleek gh renovate enum --github https://api.github.com --token ghp_xxxxx --repo owner/repo
`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := config.AutoBindFlags(cmd, map[string]string{
				"github":  "github.url",
				"token":   "github.token",
				"owned":   "github.renovate.enum.owned",
				"member":  "github.renovate.enum.member",
				"repo":    "github.renovate.enum.repo",
				"org":     "github.renovate.enum.org",
				"search":  "github.renovate.enum.search",
				"fast":    "github.renovate.enum.fast",
				"dump":    "github.renovate.enum.dump",
				"page":    "github.renovate.enum.page",
				"order-by":"github.renovate.enum.order_by",
				"extend-renovate-config-service": "github.renovate.enum.extend_renovate_config_service",
			}); err != nil {
				log.Fatal().Err(err).Msg("Failed to bind command flags to configuration keys")
			}

			if err := config.RequireConfigKeys("github.token"); err != nil {
				log.Fatal().Err(err).Msg("required configuration missing")
			}

			githubUrl := config.GetString("github.url")
			githubApiToken := config.GetString("github.token")
			owned = config.GetBool("github.renovate.enum.owned")
			member = config.GetBool("github.renovate.enum.member")
			repository = config.GetString("github.renovate.enum.repo")
			organization = config.GetString("github.renovate.enum.org")
			searchQuery = config.GetString("github.renovate.enum.search")
			fast = config.GetBool("github.renovate.enum.fast")
			dump = config.GetBool("github.renovate.enum.dump")
			page = config.GetInt("github.renovate.enum.page")
			orderBy = config.GetString("github.renovate.enum.order_by")
			extendRenovateConfigService = config.GetString("github.renovate.enum.extend_renovate_config_service")

			Enumerate(githubUrl, githubApiToken)
		},
	}

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

func Enumerate(githubUrl, githubApiToken string) {
	client := pkgscan.SetupClient(githubApiToken, githubUrl)

	opts := pkgrenovate.EnumOptions{
		GitHubURL:                   githubUrl,
		GitHubToken:                 githubApiToken,
		Owned:                       owned,
		Member:                      member,
		SearchQuery:                 searchQuery,
		Fast:                        fast,
		Dump:                        dump,
		Page:                        page,
		Repository:                  repository,
		Organization:                organization,
		OrderBy:                     orderBy,
		ExtendRenovateConfigService: extendRenovateConfigService,
	}

	pkgrenovate.RunEnumerate(client, opts)
}
