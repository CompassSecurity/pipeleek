package vuln

import (
	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgvuln "github.com/CompassSecurity/pipeleek/pkg/gitea/vuln"
	"github.com/spf13/cobra"
)

var flagBindings = map[string]string{
	"gitea": "gitea.url",
	"token": "gitea.token",
}

func NewVulnCmd() *cobra.Command {
	vulnCmd := &cobra.Command{
		Use:     "vuln",
		Short:   "Check if the installed Gitea version is vulnerable",
		Long:    "Check the installed Gitea instance version against the NIST vulnerability database to see if it is affected by any vulnerabilities.",
		Example: `pipeleek gitea vuln --token xxxxx --gitea https://gitea.mydomain.com`,
		Run:     CheckVulns,
	}

	return vulnCmd
}

func CheckVulns(cmd *cobra.Command, args []string) {
	config.NewCommandSetup(cmd).
		WithFlagBindings(flagBindings).
		RequireKeys("gitea.url", "gitea.token").
		MustBind()

	giteaUrl := config.GetString("gitea.url")
	giteaApiToken := config.GetString("gitea.token")

	pkgvuln.RunCheckVulns(giteaUrl, giteaApiToken)
}
