package enum

import (
	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgrenovate "github.com/CompassSecurity/pipeleek/pkg/gitlab/renovate/enum"
	"github.com/spf13/cobra"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

var (
	owned                       bool
	member                      bool
	projectSearchQuery          string
	fast                        bool
	dump                        bool
	page                        int
	repository                  string
	namespace                   string
	orderBy                     string
	extendRenovateConfigService string
)

func NewEnumCmd() *cobra.Command {
	enumCmd := &cobra.Command{
		Use:   "enum [no options!]",
		Short: "Enumerate Renovate configurations",
		Run: func(cmd *cobra.Command, args []string) {
			if err := config.BindCommandFlags(cmd, "gitlab.renovate.enum", map[string]string{
				"gitlab": "gitlab.url",
				"token":  "gitlab.token",
			}); err != nil {
				return
			}

			gitlabUrl := config.GetString("gitlab.url")
			gitlabApiToken := config.GetString("gitlab.token")

			if !cmd.Flags().Changed("owned") {
				owned = config.GetBool("gitlab.renovate.enum.owned")
			}
			if !cmd.Flags().Changed("member") {
				member = config.GetBool("gitlab.renovate.enum.member")
			}
			if !cmd.Flags().Changed("repo") {
				repository = config.GetString("gitlab.renovate.enum.repo")
			}
			if !cmd.Flags().Changed("namespace") {
				namespace = config.GetString("gitlab.renovate.enum.namespace")
			}
			if !cmd.Flags().Changed("search") {
				projectSearchQuery = config.GetString("gitlab.renovate.enum.search")
			}
			if !cmd.Flags().Changed("fast") {
				fast = config.GetBool("gitlab.renovate.enum.fast")
			}
			if !cmd.Flags().Changed("dump") {
				dump = config.GetBool("gitlab.renovate.enum.dump")
			}
			if !cmd.Flags().Changed("page") {
				page = config.GetInt("gitlab.renovate.enum.page")
			}
			if !cmd.Flags().Changed("order-by") {
				orderBy = config.GetString("gitlab.renovate.enum.order_by")
			}
			if !cmd.Flags().Changed("extend-renovate-config-service") {
				extendRenovateConfigService = config.GetString("gitlab.renovate.enum.extend_renovate_config_service")
			}

			Enumerate(gitlabUrl, gitlabApiToken)
		},
	}

	enumCmd.PersistentFlags().BoolVarP(&owned, "owned", "o", false, "Scan user owned projects only")
	enumCmd.PersistentFlags().BoolVarP(&member, "member", "m", false, "Scan projects the user is member of")
	enumCmd.Flags().StringVarP(&repository, "repo", "r", "", "Repository to scan for Renovate configuration (if not set, all projects will be scanned)")
	enumCmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Namespace to scan")
	enumCmd.Flags().StringVarP(&projectSearchQuery, "search", "s", "", "Query string for searching projects")
	enumCmd.Flags().BoolVarP(&fast, "fast", "f", false, "Fast mode - skip renovate config file detection, only check CIDC yml for renovate bot job (default false)")
	enumCmd.Flags().BoolVarP(&dump, "dump", "d", false, "Dump mode - save all config files to renovate-enum-out folder (default false)")
	enumCmd.Flags().IntVarP(&page, "page", "p", 1, "Page number to start fetching projects from (default 1, fetch all pages)")
	enumCmd.Flags().StringVar(&orderBy, "order-by", "created_at", "Order projects by: id, name, path, created_at, updated_at, star_count, last_activity_at, or similarity")
	enumCmd.Flags().StringVar(&extendRenovateConfigService, "extend-renovate-config-service", "", "Base URL of the resolver service e.g.  http://localhost:3000 (docker run -ti -p 3000:3000 jfrcomp/renovate-config-resolver:latest). Renovate configs can be extended by shareable preset, resolving them makes enumeration more accurate.")

	return enumCmd
}

func Enumerate(gitlabUrl, gitlabApiToken string) {
	opts := pkgrenovate.EnumOptions{
		GitlabUrl:                   gitlabUrl,
		GitlabApiToken:              gitlabApiToken,
		Owned:                       owned,
		Member:                      member,
		ProjectSearchQuery:          projectSearchQuery,
		Fast:                        fast,
		Dump:                        dump,
		Page:                        page,
		Repository:                  repository,
		Namespace:                   namespace,
		OrderBy:                     orderBy,
		ExtendRenovateConfigService: extendRenovateConfigService,
		MinAccessLevel:              int(gitlab.GuestPermissions),
	}

	pkgrenovate.RunEnumerate(opts)
}
