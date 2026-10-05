package flags

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/config"
	"github.com/CompassSecurity/pipeleek/pkg/webui"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// addBaseScanFlags adds the core scanning flags shared by all scan commands:
// threads, secrets-verification, confidence, and hit-timeout.
func addBaseScanFlags(cmd *cobra.Command, opts *config.CommonScanOptions) {
	cmd.Flags().IntVarP(&opts.MaxScanGoRoutines, "threads", "", 4, "Number of concurrent threads for scanning")
	cmd.Flags().BoolVarP(&opts.SecretsVerification, "secrets-verification", "", true,
		"Verify supported credentials with their providers (enabled by default, disable with --secrets-verification=false)")
	cmd.Flags().StringSliceVarP(&opts.ConfidenceFilter, "confidence", "", []string{},
		"Filter for confidence level, separate by comma if multiple. See readme for more info.")
	cmd.Flags().DurationVarP(&opts.HitTimeout, "hit-timeout", "", 60*time.Second,
		"Maximum time to wait for hit detection per scan item (e.g., 30s, 2m, 1h)")
	cmd.Flags().BoolVarP(&opts.WebUI, "webui", "", false,
		"Serve a local web UI for live findings on 127.0.0.1 with a random token")
}

// AddCommonScanFlags adds the standard scanning flags that are common across all platforms.
// These flags control scanning behavior, thread count, verification, and filtering.
func AddCommonScanFlags(cmd *cobra.Command, opts *config.CommonScanOptions, maxArtifactSize *string) {
	addBaseScanFlags(cmd, opts)
	cmd.Flags().BoolVarP(&opts.Artifacts, "artifacts", "a", false, "Scan artifacts")
	cmd.Flags().StringVarP(maxArtifactSize, "max-artifact-size", "", "500Mb",
		"Maximum artifact size to scan. Larger files are skipped. Format: https://pkg.go.dev/github.com/docker/go-units#FromHumanSize")
	cmd.Flags().BoolVarP(&opts.Owned, "owned", "o", false, "Scan only user owned repositories")
}

// AddCommonScanFlagsNoOwned adds standard scan flags including artifacts but excluding the
// --owned flag, for platforms that have no concept of job/repository ownership (e.g. Jenkins).
func AddCommonScanFlagsNoOwned(cmd *cobra.Command, opts *config.CommonScanOptions, maxArtifactSize *string) {
	addBaseScanFlags(cmd, opts)
	cmd.Flags().BoolVarP(&opts.Artifacts, "artifacts", "a", false, "Scan artifacts")
	cmd.Flags().StringVarP(maxArtifactSize, "max-artifact-size", "", "500Mb",
		"Maximum artifact size to scan. Larger files are skipped. Format: https://pkg.go.dev/github.com/docker/go-units#FromHumanSize")
}

// AddCommonScanFlagsNoArtifacts adds standard scan flags excluding artifact and ownership filters.
func AddCommonScanFlagsNoArtifacts(cmd *cobra.Command, opts *config.CommonScanOptions) {
	addBaseScanFlags(cmd, opts)
}

// StartScanWebUI starts the local findings UI with effective values from the command.
func StartScanWebUI(cmd *cobra.Command, targetURL string, flagBindings map[string]string) *webui.Server {
	if !config.GetBool("common.webui") {
		return nil
	}
	return webui.StartWithContextIfEnabled(true, scanContextFromCommand(cmd, targetURL, flagBindings))
}

func scanContextFromCommand(cmd *cobra.Command, targetURL string, flagBindings map[string]string) webui.ScanContext {
	scanContext := webui.ScanContext{TargetURL: targetURL}
	seen := make(map[string]struct{})
	addFlags := func(flagSet *pflag.FlagSet, includeUnbound bool) {
		flagSet.VisitAll(func(flag *pflag.Flag) {
			if flag.Name == "help" || flag.Name == "url" || flag.Name == "webui" {
				return
			}
			binding, bound := flagBindings[flag.Name]
			if !includeUnbound && !bound {
				return
			}
			if _, ok := seen[flag.Name]; ok {
				return
			}
			seen[flag.Name] = struct{}{}

			var effectiveValue interface{} = flag.Value.String()
			if bound {
				if configuredValue := config.GetViper().Get(binding); configuredValue != nil {
					effectiveValue = configuredValue
				}
			}
			if !isEnabledScanFlag(effectiveValue) {
				return
			}
			scanContext.Options = append(scanContext.Options, webui.ScanOption{
				Name:  "--" + flag.Name,
				Value: formatScanOptionValue(effectiveValue),
			})
		})
	}
	addFlags(cmd.Flags(), true)
	addFlags(cmd.PersistentFlags(), true)
	addFlags(cmd.InheritedFlags(), false)
	sort.Slice(scanContext.Options, func(i, j int) bool {
		return scanContext.Options[i].Name < scanContext.Options[j].Name
	})
	return scanContext
}

func isEnabledScanFlag(value interface{}) bool {
	switch value := value.(type) {
	case nil:
		return false
	case bool:
		return value
	case time.Duration:
		return value != 0
	case []string:
		for _, item := range value {
			if strings.TrimSpace(item) != "" {
				return true
			}
		}
		return false
	case []interface{}:
		return len(value) > 0
	case int:
		return value != 0
	case int8:
		return value != 0
	case int16:
		return value != 0
	case int32:
		return value != 0
	case int64:
		return value != 0
	case uint:
		return value != 0
	case uint8:
		return value != 0
	case uint16:
		return value != 0
	case uint32:
		return value != 0
	case uint64:
		return value != 0
	case float32:
		return value != 0
	case float64:
		return value != 0
	case string:
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			return false
		}
		if parsed, err := strconv.ParseBool(trimmed); err == nil {
			return parsed
		}
		if parsed, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
			return parsed != 0
		}
		if parsed, err := strconv.ParseFloat(trimmed, 64); err == nil {
			return parsed != 0
		}
		if parsed, err := time.ParseDuration(trimmed); err == nil {
			return parsed != 0
		}
		return true
	default:
		return strings.TrimSpace(fmt.Sprint(value)) != ""
	}
}

func formatScanOptionValue(value interface{}) string {
	switch value := value.(type) {
	case time.Duration:
		return value.String()
	case []string:
		return strings.Join(value, ", ")
	case []interface{}:
		items := make([]string, len(value))
		for i, item := range value {
			items[i] = fmt.Sprint(item)
		}
		return strings.Join(items, ", ")
	default:
		return fmt.Sprint(value)
	}
}
