package scan

import (
	"time"

	"github.com/CompassSecurity/pipeleek/internal/cmd/flags"
	circlescan "github.com/CompassSecurity/pipeleek/pkg/circle/scan"
	"github.com/CompassSecurity/pipeleek/pkg/config"
	"github.com/CompassSecurity/pipeleek/pkg/logging"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

type CircleScanOptions struct {
	config.CommonScanOptions
	Token        string
	CircleURL    string
	Organization string
	Projects     []string
	VCS          string
	Branch       string
	Statuses     []string
	Workflows    []string
	Jobs         []string
	Since        string
	Until        string
	MaxPipelines int
	IncludeTests bool
	Insights     bool
}

var options = CircleScanOptions{
	CommonScanOptions: config.DefaultCommonScanOptions(),
}

var maxArtifactSize string

func NewScanCmd() *cobra.Command {
	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan CircleCI logs and artifacts",
		Long:  `Scan CircleCI pipelines, workflows, jobs, logs, test results, and optional artifacts for secrets.`,
		Example: `
# Scan explicit project(s)
pipeleek circle scan --token <token> --project org/repo

# Restrict by branch and statuses
pipeleek circle scan --token <token> --project org/repo --branch main --status success --status failed

# Include artifacts and tests with time window
pipeleek circle scan --token <token> --project org/repo --artifacts --since 2026-01-01T00:00:00Z --until 2026-01-31T23:59:59Z
		`,
		Run: Scan,
	}

	flags.AddCommonScanFlagsNoOwned(scanCmd, &options.CommonScanOptions, &maxArtifactSize)
	scanCmd.Flags().StringVarP(&options.Token, "token", "t", "", "CircleCI API token")
	scanCmd.Flags().StringVarP(&options.CircleURL, "circle", "c", "https://circleci.com", "CircleCI base URL")
	scanCmd.Flags().StringVarP(&options.Organization, "org", "", "", "CircleCI organization slug (used to filter projects)")
	scanCmd.Flags().StringSliceVarP(&options.Projects, "project", "p", []string{}, "Project selector. Format: org/repo or vcs/org/repo")
	scanCmd.Flags().StringVarP(&options.VCS, "vcs", "", "github", "VCS provider for project selectors without prefix (github or bitbucket)")
	scanCmd.Flags().StringVarP(&options.Branch, "branch", "b", "", "Filter pipelines by branch")
	scanCmd.Flags().StringSliceVarP(&options.Statuses, "status", "", []string{}, "Filter by pipeline/workflow/job status")
	scanCmd.Flags().StringSliceVarP(&options.Workflows, "workflow", "", []string{}, "Filter by workflow name")
	scanCmd.Flags().StringSliceVarP(&options.Jobs, "job", "", []string{}, "Filter by job name")
	scanCmd.Flags().StringVarP(&options.Since, "since", "", "", "Include items created after this RFC3339 timestamp")
	scanCmd.Flags().StringVarP(&options.Until, "until", "", "", "Include items created before this RFC3339 timestamp")
	scanCmd.Flags().IntVarP(&options.MaxPipelines, "max-pipelines", "", 0, "Maximum number of pipelines to scan per project (0 = no limit)")
	scanCmd.Flags().BoolVarP(&options.IncludeTests, "tests", "", true, "Scan CircleCI test results per job")
	scanCmd.Flags().BoolVarP(&options.Insights, "insights", "", true, "Scan CircleCI workflow insights endpoints")

	return scanCmd
}

func Scan(cmd *cobra.Command, args []string) {
	if err := config.AutoBindFlags(cmd, map[string]string{
		"circle":                   "circle.url",
		"token":                    "circle.token",
		"org":                      "circle.scan.org",
		"project":                  "circle.scan.project",
		"vcs":                      "circle.scan.vcs",
		"branch":                   "circle.scan.branch",
		"status":                   "circle.scan.status",
		"workflow":                 "circle.scan.workflow",
		"job":                      "circle.scan.job",
		"since":                    "circle.scan.since",
		"until":                    "circle.scan.until",
		"max-pipelines":            "circle.scan.max_pipelines",
		"tests":                    "circle.scan.tests",
		"insights":                 "circle.scan.insights",
		"threads":                  "common.threads",
		"truffle-hog-verification": "common.trufflehog_verification",
		"max-artifact-size":        "common.max_artifact_size",
		"confidence":               "common.confidence_filter",
		"hit-timeout":              "common.hit_timeout",
	}); err != nil {
		log.Fatal().Err(err).Msg("Failed to bind command flags to configuration keys")
	}

	if err := config.RequireConfigKeys("circle.token"); err != nil {
		log.Fatal().Err(err).Msg("required configuration missing")
	}

	options.Token = config.GetString("circle.token")
	options.CircleURL = config.GetString("circle.url")
	options.Organization = config.GetString("circle.scan.org")
	options.Projects = config.GetStringSlice("circle.scan.project")
	options.VCS = config.GetString("circle.scan.vcs")
	options.Branch = config.GetString("circle.scan.branch")
	options.Statuses = config.GetStringSlice("circle.scan.status")
	options.Workflows = config.GetStringSlice("circle.scan.workflow")
	options.Jobs = config.GetStringSlice("circle.scan.job")
	options.Since = config.GetString("circle.scan.since")
	options.Until = config.GetString("circle.scan.until")
	options.MaxPipelines = config.GetInt("circle.scan.max_pipelines")
	options.IncludeTests = config.GetBool("circle.scan.tests")
	options.Insights = config.GetBool("circle.scan.insights")
	options.MaxScanGoRoutines = config.GetInt("common.threads")
	options.TruffleHogVerification = config.GetBool("common.trufflehog_verification")
	options.ConfidenceFilter = config.GetStringSlice("common.confidence_filter")
	maxArtifactSize = config.GetString("common.max_artifact_size")
	if hitTimeoutSeconds := config.GetInt("common.hit_timeout"); hitTimeoutSeconds > 0 {
		options.HitTimeout = time.Duration(hitTimeoutSeconds) * time.Second
	}

	if err := config.ValidateURL(options.CircleURL, "CircleCI URL"); err != nil {
		log.Fatal().Err(err).Msg("Invalid CircleCI URL")
	}
	if err := config.ValidateToken(options.Token, "CircleCI API token"); err != nil {
		log.Fatal().Err(err).Msg("Invalid CircleCI API token")
	}
	if err := config.ValidateThreadCount(options.MaxScanGoRoutines); err != nil {
		log.Fatal().Err(err).Msg("Invalid thread count")
	}

	scanOpts, err := circlescan.InitializeOptions(circlescan.InitializeOptionsInput{
		Token:                  options.Token,
		CircleURL:              options.CircleURL,
		Organization:           options.Organization,
		Projects:               options.Projects,
		VCS:                    options.VCS,
		Branch:                 options.Branch,
		Statuses:               options.Statuses,
		WorkflowNames:          options.Workflows,
		JobNames:               options.Jobs,
		Since:                  options.Since,
		Until:                  options.Until,
		MaxPipelines:           options.MaxPipelines,
		IncludeTests:           options.IncludeTests,
		IncludeInsights:        options.Insights,
		Artifacts:              options.Artifacts,
		MaxArtifactSize:        maxArtifactSize,
		ConfidenceFilter:       options.ConfidenceFilter,
		MaxScanGoRoutines:      options.MaxScanGoRoutines,
		TruffleHogVerification: options.TruffleHogVerification,
		HitTimeout:             options.HitTimeout,
	})
	if err != nil {
		log.Fatal().Err(err).Msg("Failed initializing CircleCI scan options")
	}

	scanner := circlescan.NewScanner(scanOpts)
	logging.RegisterStatusHook(func() *zerolog.Event { return scanner.Status() })

	if err := scanner.Scan(); err != nil {
		log.Fatal().Err(err).Msg("Scan failed")
	}
}
