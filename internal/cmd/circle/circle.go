package circle

import (
	"github.com/CompassSecurity/pipeleek/internal/cmd/circle/scan"
	"github.com/spf13/cobra"
)

var (
	circleApiToken string
	circleUrl      string
)

func NewCircleRootCmd() *cobra.Command {
	circleCmd := &cobra.Command{
		Use:     "circle [command]",
		Short:   "CircleCI related commands",
		GroupID: "CircleCI",
	}

	circleCmd.AddCommand(scan.NewScanCmd())

	circleCmd.PersistentFlags().StringVarP(&circleUrl, "url", "u", "", "CircleCI instance URL")
	circleCmd.PersistentFlags().StringVarP(&circleApiToken, "token", "t", "", "CircleCI API Token")

	return circleCmd
}
