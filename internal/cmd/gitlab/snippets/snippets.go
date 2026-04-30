package snippets

import (
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/snippets/scan"
	"github.com/spf13/cobra"
)

func NewSnippetsRootCmd() *cobra.Command {
	snippetsCmd := &cobra.Command{
		Use:   "snippets",
		Short: "GitLab snippets related commands",
	}

	snippetsCmd.AddCommand(scan.NewScanCmd())

	return snippetsCmd
}
