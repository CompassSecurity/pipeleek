package flags

import (
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/config"
	"github.com/spf13/cobra"
)

// AddCommonScanFlags adds the standard scanning flags that are common across all platforms.
// These flags control scanning behavior, thread count, verification, and filtering.
func AddCommonScanFlags(cmd *cobra.Command, opts *config.CommonScanOptions, maxArtifactSize *string) {
	cmd.Flags().IntVarP(&opts.MaxScanGoRoutines, "threads", "", 4, "Number of concurrent threads for scanning")
	cmd.Flags().BoolVarP(&opts.TruffleHogVerification, "truffle-hog-verification", "", true,
		"Enable TruffleHog credential verification to actively test found credentials and only report verified ones (enabled by default, disable with --truffle-hog-verification=false)")
	cmd.Flags().BoolVarP(&opts.Artifacts, "artifacts", "a", false, "Scan artifacts")
	cmd.Flags().StringVarP(maxArtifactSize, "max-artifact-size", "", "500Mb",
		"Maximum artifact size to scan. Larger files are skipped. Format: https://pkg.go.dev/github.com/docker/go-units#FromHumanSize")
	cmd.Flags().StringSliceVarP(&opts.ConfidenceFilter, "confidence", "", []string{},
		"Filter for confidence level, separate by comma if multiple. See readme for more info.")
	cmd.Flags().BoolVarP(&opts.Owned, "owned", "o", false, "Scan only user owned repositories")
	cmd.Flags().DurationVarP(&opts.HitTimeout, "hit-timeout", "", 60*time.Second,
		"Maximum time to wait for hit detection per scan item (e.g., 30s, 2m, 1h)")
}


