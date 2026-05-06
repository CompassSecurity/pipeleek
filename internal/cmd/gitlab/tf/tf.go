package tf

import (
	"fmt"
	"time"

	"github.com/CompassSecurity/pipeleek/internal/cmd/flags"
	"github.com/CompassSecurity/pipeleek/pkg/config"
	tfpkg "github.com/CompassSecurity/pipeleek/pkg/gitlab/tf"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

type TFCommandOptions struct {
	config.CommonScanOptions
	OutputDir string
}

var options = TFCommandOptions{CommonScanOptions: config.DefaultCommonScanOptions()}
var flagBindings = map[string]string{
	"gitlab":                   "gitlab.url",
	"token":                    "gitlab.token",
	"output-dir":               "gitlab.tf.output_dir",
	"threads":                  "common.threads",
	"truffle-hog-verification": "common.trufflehog_verification",
	"confidence":               "common.confidence_filter",
	"hit-timeout":              "common.hit_timeout",
}

func NewTFCmd() *cobra.Command {
	tfCmd := &cobra.Command{
		Use:   "tf",
		Short: "Scan Terraform/OpenTofu state files for secrets",
		Long: `Scan GitLab Terraform/OpenTofu state files for secrets

This command iterates through all projects where you have maintainer access,
lists GitLab-managed Terraform states, downloads them locally, and scans them
for secrets using TruffleHog.

GitLab stores Terraform state natively when using the Terraform HTTP backend.
Each project can have multiple named state files.`,
		Example: `# Scan all Terraform states in projects with maintainer access
pipeleek gl tf --token glpat-xxxxxxxxxxx --gitlab https://gitlab.example.com

# Save state files to custom directory
pipeleek gl tf --token glpat-xxxxxxxxxxx --gitlab https://gitlab.example.com --output-dir ./tf-states

# Use more threads for TruffleHog scanning
pipeleek gl tf --token glpat-xxxxxxxxxxx --gitlab https://gitlab.example.com --threads 10

# Scan with high confidence filter only
pipeleek gl tf --token glpat-xxxxxxxxxxx --gitlab https://gitlab.example.com --confidence high`,
		Run: tfRun,
	}

	tfCmd.Flags().StringVar(&options.OutputDir, "output-dir", "./terraform-states", "Directory to save downloaded state files")
	flags.AddCommonScanFlagsNoArtifacts(tfCmd, &options.CommonScanOptions)

	return tfCmd
}

func tfRun(cmd *cobra.Command, args []string) {
	// Unified command setup with flag binding, required key validation, and validators
	config.NewCommandSetup(cmd).
		WithFlagBindings(flagBindings).
		RequireKeys("gitlab.url", "gitlab.token").
		AddValidator(func() error { return config.ValidateURL(config.GetString("gitlab.url"), "GitLab URL") }).
		AddValidator(func() error { return config.ValidateToken(config.GetString("gitlab.token"), "GitLab API Token") }).
		AddValidator(func() error { return config.ValidateThreadCount(config.GetInt("common.threads")) }).
		MustBind()

	// Load configuration values
	gitlabUrl := config.GetString("gitlab.url")
	gitlabApiToken := config.GetString("gitlab.token")
	options.OutputDir = config.GetString("gitlab.tf.output_dir")
	options.MaxScanGoRoutines = config.GetInt("common.threads")
	options.ConfidenceFilter = config.GetStringSlice("common.confidence_filter")
	options.TruffleHogVerification = config.GetBool("common.trufflehog_verification")
	hitTimeoutRaw := config.GetString("common.hit_timeout")
	hitTimeout, err := time.ParseDuration(hitTimeoutRaw)
	if err != nil {
		log.Fatal().Err(fmt.Errorf("invalid hit-timeout %q: %w", hitTimeoutRaw, err)).Msg("Invalid hit timeout")
	}
	options.HitTimeout = hitTimeout

	tfOptions := tfpkg.TFOptions{
		GitlabUrl:              gitlabUrl,
		GitlabApiToken:         gitlabApiToken,
		OutputDir:              options.OutputDir,
		Threads:                options.MaxScanGoRoutines,
		ConfidenceFilter:       options.ConfidenceFilter,
		TruffleHogVerification: options.TruffleHogVerification,
		HitTimeout:             options.HitTimeout,
	}

	tfpkg.ScanTerraformStates(tfOptions)

	log.Info().Msg("Done, Bye Bye 🏳️‍🌈🔥")
}
