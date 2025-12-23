package enum

import (
	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgrenovate "github.com/CompassSecurity/pipeleek/pkg/gitlab/renovate/enum"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func NewEnumCmd() *cobra.Command {
	enumCmd := &cobra.Command{
		Use:   "enum [no options!]",
		Short: "Enumerate Renovate configurations",
		Run: func(cmd *cobra.Command, args []string) {
			if err := config.BindCommandFlags(cmd, "gitlab.renovate.enum", nil); err != nil {
				log.Fatal().Err(err).Msg("Failed to bind flags")
			}

			gitlabUrl := config.GetString("gitlab.url")
			gitlabApiToken := config.GetString("gitlab.token")
			owned := config.GetBool("gitlab.renovate.enum.owned")
			member := config.GetBool("gitlab.renovate.enum.member")
			repository := config.GetString("gitlab.renovate.enum.repo")
			namespace := config.GetString("gitlab.renovate.enum.namespace")
			projectSearchQuery := config.GetString("gitlab.renovate.enum.search")
			fast := config.GetBool("gitlab.renovate.enum.fast")
			dump := config.GetBool("gitlab.renovate.enum.dump")
			page := config.GetInt("gitlab.renovate.enum.page")
			orderBy := config.GetString("gitlab.renovate.enum.order_by")
			extendRenovateConfigService := config.GetString("gitlab.renovate.enum.extend_renovate_config_service")

			Enumerate(gitlabUrl, gitlabApiToken, owned, member, repository, namespace, projectSearchQuery, fast, dump, page, orderBy, extendRenovateConfigService)
		},
	}

	enumCmd.PersistentFlags().BoolP("owned", "o", false, "Scan user owned projects only")
	enumCmd.PersistentFlags().BoolP("member", "m", false, "Scan projects the user is member of")
	enumCmd.Flags().StringP("repo", "r", "", "Repository to scan for Renovate configuration (if not set, all projects will be scanned)")
	enumCmd.Flags().StringP("namespace", "n", "", "Namespace to scan")
	enumCmd.Flags().StringP("search", "s", "", "Query string for searching projects")
	enumCmd.Flags().BoolP("fast", "f", false, "Fast mode - skip renovate config file detection, only check CIDC yml for renovate bot job (default false)")
	enumCmd.Flags().BoolP("dump", "d", false, "Dump mode - save all config files to renovate-enum-out folder (default false)")
	enumCmd.Flags().IntP("page", "p", 1, "Page number to start fetching projects from (default 1, fetch all pages)")
	enumCmd.Flags().String("order-by", "created_at", "Order projects by: id, name, path, created_at, updated_at, star_count, last_activity_at, or similarity")
	enumCmd.Flags().String("extend-renovate-config-service", "", "Base URL of the resolver service e.g.  http://localhost:3000 (docker run -ti -p 3000:3000 jfrcomp/renovate-config-resolver:latest). Renovate configs can be extended by shareable preset, resolving them makes enumeration more accurate.")

	return enumCmd
}

func Enumerate(gitlabUrl, gitlabApiToken string, owned, member bool, repository, namespace, projectSearchQuery string, fast, dump bool, page int, orderBy, extendRenovateConfigService string) {
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
