package scan

import (
	"fmt"
	"time"

	"github.com/CompassSecurity/pipeleek/internal/cmd/flags"
	"github.com/CompassSecurity/pipeleek/pkg/config"
	jenkinsscan "github.com/CompassSecurity/pipeleek/pkg/jenkins/scan"
	"github.com/CompassSecurity/pipeleek/pkg/logging"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

type JenkinsScanOptions struct {
	config.CommonScanOptions
	JenkinsURL string
	Username   string
	Token      string
	Folder     string
	Job        string
	MaxBuilds  int
}

var options = JenkinsScanOptions{
	CommonScanOptions: config.DefaultCommonScanOptions(),
}

var maxArtifactSize string
var flagBindings = map[string]string{
	"jenkins":                  "jenkins.url",
	"username":                 "jenkins.username",
	"token":                    "jenkins.token",
	"folder":                   "jenkins.scan.folder",
	"job":                      "jenkins.scan.job",
	"max-builds":               "jenkins.scan.max_builds",
	"artifacts":                "jenkins.scan.artifacts",
	"threads":                  "common.threads",
	"truffle-hog-verification": "common.trufflehog_verification",
	"max-artifact-size":        "common.max_artifact_size",
	"confidence":               "common.confidence_filter",
	"hit-timeout":              "common.hit_timeout",
}

func NewScanCmd() *cobra.Command {
	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan Jenkins jobs",
		Long:  `Scan Jenkins job logs, artifacts, job definitions, and exposed environment variables for secrets.`,
		Example: `
# Scan all accessible jobs on the Jenkins instance
pipeleek jenkins scan --jenkins https://jenkins.example.com --username admin --token token_value

# Scan only a folder recursively
pipeleek jenkins scan --jenkins https://jenkins.example.com --username admin --token token_value --folder team-a

# Scan one specific job path
pipeleek jenkins scan --jenkins https://jenkins.example.com --username admin --token token_value --job team-a/service-a

# Limit builds per job and include artifacts
pipeleek jenkins scan --jenkins https://jenkins.example.com --username admin --token token_value --max-builds 20 --artifacts
		`,
		Run: Scan,
	}

	flags.AddCommonScanFlagsNoOwned(scanCmd, &options.CommonScanOptions, &maxArtifactSize)
	scanCmd.Flags().StringVarP(&options.JenkinsURL, "jenkins", "j", "", "Jenkins base URL")
	scanCmd.Flags().StringVarP(&options.Username, "username", "u", "", "Jenkins username")
	scanCmd.Flags().StringVarP(&options.Token, "token", "t", "", "Jenkins API token")
	scanCmd.Flags().StringVarP(&options.Folder, "folder", "f", "", "Jenkins folder path to scan recursively (e.g. team-a/platform)")
	scanCmd.Flags().StringVarP(&options.Job, "job", "", "", "Specific Jenkins job path to scan (e.g. team-a/service-a)")
	scanCmd.Flags().IntVarP(&options.MaxBuilds, "max-builds", "", 25, "Maximum builds to scan per job (0 = all builds)")
	scanCmd.MarkFlagsMutuallyExclusive("folder", "job")

	return scanCmd
}

func Scan(cmd *cobra.Command, args []string) {
	// Unified command setup with flag binding, required key validation, and validators
	config.NewCommandSetup(cmd).
		WithFlagBindings(flagBindings).
		RequireKeys("jenkins.url", "jenkins.username", "jenkins.token").
		AddValidator(func() error { return config.ValidateURL(config.GetString("jenkins.url"), "Jenkins URL") }).
		AddValidator(func() error { return config.ValidateToken(config.GetString("jenkins.username"), "Jenkins Username") }).
		AddValidator(func() error { return config.ValidateToken(config.GetString("jenkins.token"), "Jenkins API Token") }).
		AddValidator(func() error { return config.ValidateThreadCount(config.GetInt("common.threads")) }).
		MustBind()

	// Load configuration values
	options.JenkinsURL = config.GetString("jenkins.url")
	options.Username = config.GetString("jenkins.username")
	options.Token = config.GetString("jenkins.token")
	options.Folder = config.GetString("jenkins.scan.folder")
	options.Job = config.GetString("jenkins.scan.job")
	options.MaxBuilds = config.GetInt("jenkins.scan.max_builds")
	options.Artifacts = config.GetBool("jenkins.scan.artifacts")
	options.MaxScanGoRoutines = config.GetInt("common.threads")
	options.TruffleHogVerification = config.GetBool("common.trufflehog_verification")
	maxArtifactSize = config.GetString("common.max_artifact_size")
	options.ConfidenceFilter = config.GetStringSlice("common.confidence_filter")
	hitTimeoutRaw := config.GetString("common.hit_timeout")
	hitTimeout, err := time.ParseDuration(hitTimeoutRaw)
	if err != nil {
		log.Fatal().Err(fmt.Errorf("invalid hit-timeout %q: %w", hitTimeoutRaw, err)).Msg("Invalid hit timeout")
	}
	options.HitTimeout = hitTimeout

	scanOpts, err := jenkinsscan.InitializeOptions(
		options.Username,
		options.Token,
		options.JenkinsURL,
		options.Folder,
		options.Job,
		maxArtifactSize,
		options.Artifacts,
		options.TruffleHogVerification,
		options.MaxBuilds,
		options.MaxScanGoRoutines,
		options.ConfidenceFilter,
		options.HitTimeout,
	)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed initializing scan options")
	}

	scanner := jenkinsscan.NewScanner(scanOpts)
	logging.RegisterStatusHook(func() *zerolog.Event { return scanner.Status() })

	if err := scanner.Scan(); err != nil {
		log.Fatal().Err(err).Msg("Scan failed")
	}
}
