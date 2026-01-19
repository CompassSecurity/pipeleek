package tf

import (
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
var maxArtifactSize string

func NewTFCmd() *cobra.Command {
	tfCmd := &cobra.Command{
		Use:   "tf",
		Short: "Scan Terraform/OpenTofu state files for secrets",
		Long: `Scan GitLab Terraform/OpenTofu state files for secrets

This command iterates through all projects where you have maintainer access,
checks for Terraform state files stored in GitLab, downloads them locally,
and scans them for secrets using TruffleHog.

GitLab stores Terraform state natively when using the Terraform HTTP backend.
Each project can have multiple named state files.`,
		Example: `# Scan all Terraform states in projects with maintainer access
pipeleek gl tf --token glpat-xxxxxxxxxxx --gitlab https://gitlab.example.com

# Save state files to custom directory
pipeleek gl tf --token glpat-xxxxxxxxxxx --gitlab https://gitlab.example.com --output-dir ./tf-states

# Use more threads for faster scanning
pipeleek gl tf --token glpat-xxxxxxxxxxx --gitlab https://gitlab.example.com --threads 10

# Scan with high confidence filter only
pipeleek gl tf --token glpat-xxxxxxxxxxx --gitlab https://gitlab.example.com --confidence high`,
		Run: tfRun,
	}

	// Command-specific flags
	tfCmd.Flags().StringVar(&options.OutputDir, "output-dir", "./terraform-states", "Directory to save downloaded state files")

	// Common scan flags (threads, verification, confidence, hit-timeout, etc.)
	flags.AddCommonScanFlags(tfCmd, &options.CommonScanOptions, &maxArtifactSize)

	return tfCmd
}

func tfRun(cmd *cobra.Command, args []string) {
	if err := config.AutoBindFlags(cmd, map[string]string{
		"gitlab":                   "gitlab.url",
		"token":                    "gitlab.token",
		"output-dir":               "gitlab.tf.output_dir",
		"threads":                  "common.threads",
		"truffle-hog-verification": "common.trufflehog_verification",
		"confidence":               "common.confidence_filter",
		"hit-timeout":              "common.hit_timeout",
	}); err != nil {
		log.Fatal().Err(err).Msg("Failed to bind command flags to configuration keys")
	}

	if err := config.RequireConfigKeys("gitlab.url", "gitlab.token"); err != nil {
		log.Fatal().Err(err).Msg("required configuration missing")
	}

	gitlabUrl := config.GetString("gitlab.url")
	gitlabApiToken := config.GetString("gitlab.token")
	options.OutputDir = config.GetString("gitlab.tf.output_dir")
	options.MaxScanGoRoutines = config.GetInt("common.threads")
	options.ConfidenceFilter = config.GetStringSlice("common.confidence_filter")
	options.TruffleHogVerification = config.GetBool("common.trufflehog_verification")
	// HitTimeout comes from flags via AddCommonScanFlags; keep as-is

	if err := config.ValidateURL(gitlabUrl, "GitLab URL"); err != nil {
		log.Fatal().Err(err).Msg("Invalid GitLab URL")
	}
	if err := config.ValidateToken(gitlabApiToken, "GitLab API Token"); err != nil {
		log.Fatal().Err(err).Msg("Invalid GitLab API Token")
	}
	if err := config.ValidateThreadCount(options.MaxScanGoRoutines); err != nil {
		log.Fatal().Err(err).Msg("Invalid thread count")
	}

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
