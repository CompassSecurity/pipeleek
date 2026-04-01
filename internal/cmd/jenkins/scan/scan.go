package scan

import (
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
	if err := config.AutoBindFlags(cmd, map[string]string{
		"jenkins":                  "jenkins.url",
		"username":                 "jenkins.username",
		"token":                    "jenkins.token",
		"folder":                   "jenkins.scan.folder",
		"job":                      "jenkins.scan.job",
		"max-builds":               "jenkins.scan.max_builds",
		"threads":                  "common.threads",
		"truffle-hog-verification": "common.trufflehog_verification",
		"max-artifact-size":        "common.max_artifact_size",
		"confidence":               "common.confidence_filter",
		"hit-timeout":              "common.hit_timeout",
	}); err != nil {
		log.Fatal().Err(err).Msg("Failed to bind command flags to configuration keys")
	}

	if err := config.RequireConfigKeys("jenkins.url", "jenkins.username", "jenkins.token"); err != nil {
		log.Fatal().Err(err).Msg("required configuration missing")
	}

	options.JenkinsURL = config.GetString("jenkins.url")
	options.Username = config.GetString("jenkins.username")
	options.Token = config.GetString("jenkins.token")
	options.Folder = config.GetString("jenkins.scan.folder")
	options.Job = config.GetString("jenkins.scan.job")
	options.MaxBuilds = config.GetInt("jenkins.scan.max_builds")
	options.MaxScanGoRoutines = config.GetInt("common.threads")
	options.TruffleHogVerification = config.GetBool("common.trufflehog_verification")
	maxArtifactSize = config.GetString("common.max_artifact_size")
	options.ConfidenceFilter = config.GetStringSlice("common.confidence_filter")

	if err := config.ValidateURL(options.JenkinsURL, "Jenkins URL"); err != nil {
		log.Fatal().Err(err).Msg("Invalid Jenkins URL")
	}
	if err := config.ValidateToken(options.Username, "Jenkins Username"); err != nil {
		log.Fatal().Err(err).Msg("Invalid Jenkins Username")
	}
	if err := config.ValidateToken(options.Token, "Jenkins API Token"); err != nil {
		log.Fatal().Err(err).Msg("Invalid Jenkins API Token")
	}
	if err := config.ValidateThreadCount(options.MaxScanGoRoutines); err != nil {
		log.Fatal().Err(err).Msg("Invalid thread count")
	}

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
