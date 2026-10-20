package release

import (
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/release/scan"
	"github.com/spf13/cobra"
)

func NewReleaseRootCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "release", Short: "GitLab release related commands"}
	cmd.AddCommand(scan.NewScanCmd())
	return cmd
}
