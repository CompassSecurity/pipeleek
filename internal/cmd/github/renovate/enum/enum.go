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

# Enumerate specific organization
pipeleek gh renovate enum --github https://api.github.com --token ghp_xxxxx --org mycompany

# Enumerate with config file dump
pipeleek gh renovate enum --github https://api.github.com --token ghp_xxxxx --owned --dump

# Fast mode (skip config file detection)
pipeleek gh renovate enum --github https://api.github.com --token ghp_xxxxx --org myorg --fast

# Enumerate specific repository
pipeleek gh renovate enum --github https://api.github.com --token ghp_xxxxx --repo owner/repo
`,
		PreRun: func(cmd *cobra.Command, args []string) {
			// Bind parent flags to config
			if err := config.BindCommandFlags(cmd.Parent(), "github.renovate", map[string]string{
				"github": "github.url",
				"token":  "github.token",
			}); err != nil {
				log.Fatal().Err(err).Msg("Failed to bind parent flags")
			}
		},
		Run: func(cmd *cobra.Command, args []string) {
			if err := config.BindCommandFlags(cmd, "github.renovate.enum", nil); err != nil {
				log.Fatal().Err(err).Msg("Failed to bind flags to config")
			}

			// Get github URL and token from config (supports all three methods)
			githubUrl := config.GetString("github.url")
			githubApiToken := config.GetString("github.token")

			if githubUrl == "" {
				log.Fatal().Msg("GitHub URL is required (use --github flag, config file, or PIPELEEK_GITHUB_URL env var)")
			}
			if githubApiToken == "" {
				log.Fatal().Msg("GitHub token is required (use --token flag, config file, or PIPELEEK_GITHUB_TOKEN env var)")
			}

			// All flags can come from config, CLI flags, or env vars via Viper
			if !cmd.Flags().Changed("owned") {
				owned = config.GetBool("github.renovate.enum.owned")
			}
			if !cmd.Flags().Changed("member") {
				member = config.GetBool("github.renovate.enum.member")
			}
			if !cmd.Flags().Changed("repo") {
				repository = config.GetString("github.renovate.enum.repo")
			}
			if !cmd.Flags().Changed("org") {
				organization = config.GetString("github.renovate.enum.org")
			}
			if !cmd.Flags().Changed("search") {
				searchQuery = config.GetString("github.renovate.enum.search")
			}
			if !cmd.Flags().Changed("fast") {
				fast = config.GetBool("github.renovate.enum.fast")
			}
			if !cmd.Flags().Changed("dump") {
				dump = config.GetBool("github.renovate.enum.dump")
			}
			if !cmd.Flags().Changed("page") {
				page = config.GetInt("github.renovate.enum.page")
			}
			if !cmd.Flags().Changed("order-by") {
				orderBy = config.GetString("github.renovate.enum.order_by")
			}
			if !cmd.Flags().Changed("extend-renovate-config-service") {
				extendRenovateConfigService = config.GetString("github.renovate.enum.extend_renovate_config_service")
			}

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
