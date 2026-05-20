package bitbucket

import (
	"github.com/CompassSecurity/pipeleek/internal/cmd/bitbucket/scan"
	"github.com/spf13/cobra"
)

var (
	bitbucketApiToken string
	bitbucketUrl      string
)

func NewBitBucketRootCmd() *cobra.Command {
	bbCmd := &cobra.Command{
		Use:     "bb [command]",
		Short:   "BitBucket related commands",
		GroupID: "BitBucket",
	}

	bbCmd.AddCommand(scan.NewScanCmd())

	bbCmd.PersistentFlags().StringVarP(&bitbucketUrl, "url", "b", "https://api.bitbucket.org/2.0", "BitBucket instance URL")
	bbCmd.PersistentFlags().StringVarP(&bitbucketApiToken, "token", "t", "", "BitBucket API Token")

	return bbCmd
}
