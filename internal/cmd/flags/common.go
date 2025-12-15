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

// ApplyConfigToCommonScanOptions applies config file values to common scan options if they weren't set via CLI flags.
// This respects the priority: CLI flags > config file > defaults.
func ApplyConfigToCommonScanOptions(cmd *cobra.Command, opts *config.CommonScanOptions, maxArtifactSize *string) {
	// Apply threads from config if not set via flag
	if !cmd.Flags().Changed("threads") {
		opts.MaxScanGoRoutines = config.GetIntValue(cmd, "threads", func(c *config.Config) int {
			return c.Common.Threads
		})
	}

	// Apply truffle-hog-verification from config if not set via flag
	if !cmd.Flags().Changed("truffle-hog-verification") {
		opts.TruffleHogVerification = config.GetBoolValue(cmd, "truffle-hog-verification", func(c *config.Config) bool {
			return c.Common.TruffleHogVerification
		})
	}

	// Apply max-artifact-size from config if not set via flag
	if !cmd.Flags().Changed("max-artifact-size") {
		*maxArtifactSize = config.GetStringValue(cmd, "max-artifact-size", func(c *config.Config) string {
			return c.Common.MaxArtifactSize
		})
	}

	// Apply confidence filter from config if not set via flag
	if !cmd.Flags().Changed("confidence") {
		opts.ConfidenceFilter = config.GetStringSliceValue(cmd, "confidence", func(c *config.Config) []string {
			return c.Common.ConfidenceFilter
		})
	}

	// Note: hit-timeout uses Duration type, which needs special handling
	// For now, we'll skip it since it's more complex and less commonly configured
}
