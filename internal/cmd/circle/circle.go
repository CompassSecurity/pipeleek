package circle

import (
	"github.com/CompassSecurity/pipeleek/internal/cmd/circle/scan"
	"github.com/spf13/cobra"
)

func NewCircleRootCmd() *cobra.Command {
	circleCmd := &cobra.Command{
		Use:     "circle [command]",
		Short:   "CircleCI related commands",
		GroupID: "CircleCI",
	}

	circleCmd.AddCommand(scan.NewScanCmd())

	return circleCmd
}
