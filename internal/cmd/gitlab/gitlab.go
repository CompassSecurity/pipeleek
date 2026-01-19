package gitlab

import (
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/cicd"
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/enum"
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/renovate"
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/runners"
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/scan"
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/schedule"
	securefiles "github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/secureFiles"
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/tf"
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/variables"
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/vuln"
	"github.com/spf13/cobra"
)

var (
	gitlabApiToken string
	gitlabUrl      string
)

func NewGitLabRootCmd() *cobra.Command {
	glCmd := &cobra.Command{
		Use:   "gl [command]",
		Short: "GitLab related commands",
		Long: `Commands to enumerate and exploit GitLab instances.
### GitLab Proxy Support

> **Note:** Proxying is currently supported only for GitLab commands.

Since Go binaries aren't compatible with Proxychains, you can set a proxy using the HTTP_PROXY environment variable.

For HTTP proxy (e.g., Burp Suite):
<code>HTTP_PROXY=http://127.0.0.1:8080 pipeleek gl scan --token glpat-xxxxxxxxxxx --gitlab https://gitlab.com</code>

For SOCKS5 proxy:
<code>HTTP_PROXY=socks5://127.0.0.1:8080 pipeleek gl scan --token glpat-xxxxxxxxxxx --gitlab https://gitlab.com</code>
		`,
		GroupID: "GitLab",
	}

	glCmd.AddCommand(scan.NewScanCmd())
	glCmd.AddCommand(runners.NewRunnersRootCmd())
	glCmd.AddCommand(vuln.NewVulnCmd())
	glCmd.AddCommand(variables.NewVariablesCmd())
	glCmd.AddCommand(securefiles.NewSecureFilesCmd())
	glCmd.AddCommand(enum.NewEnumCmd())
	glCmd.AddCommand(renovate.NewRenovateRootCmd())
	glCmd.AddCommand(cicd.NewCiCdCmd())
	glCmd.AddCommand(schedule.NewScheduleCmd())
	glCmd.AddCommand(tf.NewTFCmd())

	glCmd.PersistentFlags().StringVarP(&gitlabUrl, "gitlab", "g", "", "GitLab instance URL")
	glCmd.PersistentFlags().StringVarP(&gitlabApiToken, "token", "t", "", "GitLab API Token")

	return glCmd
}
