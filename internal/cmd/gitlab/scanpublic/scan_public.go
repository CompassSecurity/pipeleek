package scanpublic

import (
	"fmt"
	"time"

	"github.com/CompassSecurity/pipeleek/internal/cmd/flags"
	"github.com/CompassSecurity/pipeleek/pkg/config"
	gitlabscan "github.com/CompassSecurity/pipeleek/pkg/gitlab/scan"
	"github.com/CompassSecurity/pipeleek/pkg/logging"
	"github.com/CompassSecurity/pipeleek/pkg/scanner/detectors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

type ScanPublicOptions struct {
	config.CommonScanOptions
	ProjectSearchQuery string
	Repository         string
	Namespace          string
	JobLimit           int
	QueueFolder        string
}

var options = ScanPublicOptions{
	CommonScanOptions: config.DefaultCommonScanOptions(),
}

var maxArtifactSize string

var flagBindings = map[string]string{
	"url":                       "gitlab.url",
	"search":                   "gitlab.scan_public.search",
	"project":                  "gitlab.scan_public.project",
	"group":                    "gitlab.scan_public.group",
	"job-limit":                "gitlab.scan_public.job_limit",
	"queue":                    "gitlab.scan_public.queue",
	"artifacts":                "gitlab.scan_public.artifacts",
	"threads":                  "common.threads",
	"truffle-hog-verification": "common.trufflehog_verification",
	"max-artifact-size":        "common.max_artifact_size",
	"confidence":               "common.confidence_filter",
	"hit-timeout":              "common.hit_timeout",
}

func NewScanPublicCmd() *cobra.Command {
	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan public GitLab pipelines without an account",
		Long: `Scan public GitLab project pipelines for secrets in job traces and optionally artifacts.

This command does not require an API token and only covers resources that are publicly accessible.
Dotenv artifacts are intentionally not scanned in this mode because they require a UI session cookie.`,
		Example: `
# Scan public project pipelines and traces
pipeleek gluna scan --url https://gitlab.example.com

# Scan public pipelines with artifacts and tuned performance
pipeleek gluna scan --url https://gitlab.example.com --artifacts --job-limit 10 --max-artifact-size 200Mb --threads 8

# Scan one public project
pipeleek gluna scan --url https://gitlab.example.com --project mygroup/myproject

# Scan all public projects in a group
pipeleek gluna scan --url https://gitlab.example.com --group mygroup
		`,
		Run: ScanPublic,
	}

	scanCmd.Flags().StringP("url", "g", "", "GitLab instance URL")
	flags.AddCommonScanFlagsNoArtifacts(scanCmd, &options.CommonScanOptions)
	scanCmd.Flags().BoolVarP(&options.Artifacts, "artifacts", "a", false, "Scan artifacts")
	scanCmd.Flags().StringVarP(&maxArtifactSize, "max-artifact-size", "", "500Mb",
		"Maximum artifact size to scan. Larger files are skipped. Format: https://pkg.go.dev/github.com/docker/go-units#FromHumanSize")
	scanCmd.Flags().StringVarP(&options.ProjectSearchQuery, "search", "s", "", "Query string for searching public projects")
	scanCmd.Flags().StringVarP(&options.Repository, "project", "p", "", "Single public project to scan, format: group/project")
	scanCmd.Flags().StringVarP(&options.Namespace, "group", "n", "", "Group to scan (all public projects in the group will be scanned)")
	scanCmd.Flags().IntVarP(&options.JobLimit, "job-limit", "j", 0, "Scan a max number of pipeline jobs - trade speed vs coverage. 0 scans all and is the default.")
	scanCmd.Flags().StringVarP(&options.QueueFolder, "queue", "q", "", "Relative or absolute folderpath where the queue files will be stored. Defaults to system tmp. Non-existing folders will be created.")

	return scanCmd
}

func ScanPublic(cmd *cobra.Command, args []string) {
	config.NewCommandSetup(cmd).
		WithFlagBindings(flagBindings).
		RequireKeys("gitlab.url").
		AddValidator(func() error { return config.ValidateURL(config.GetString("gitlab.url"), "GitLab URL") }).
		AddValidator(func() error { return config.ValidateThreadCount(config.GetInt("common.threads")) }).
		MustBind()

	gitlabURL := config.GetString("gitlab.url")
	projectSearchQuery := config.GetString("gitlab.scan_public.search")
	repository := config.GetString("gitlab.scan_public.project")
	namespace := config.GetString("gitlab.scan_public.group")
	jobLimit := config.GetInt("gitlab.scan_public.job_limit")
	queueFolder := config.GetString("gitlab.scan_public.queue")
	artifacts := config.GetBool("gitlab.scan_public.artifacts")
	threads := config.GetInt("common.threads")
	truffleHogVerification := config.GetBool("common.trufflehog_verification")
	maxArtifactSize = config.GetString("common.max_artifact_size")
	confidenceFilter := config.GetStringSlice("common.confidence_filter")
	hitTimeoutRaw := config.GetString("common.hit_timeout")
	hitTimeout, err := time.ParseDuration(hitTimeoutRaw)
	if err != nil {
		log.Fatal().Err(fmt.Errorf("invalid hit-timeout %q: %w", hitTimeoutRaw, err)).Msg("Invalid hit timeout")
	}

	detectors.SetGitLabURL(gitlabURL)
	scanOpts, err := gitlabscan.InitializeOptions(
		gitlabURL,
		"",
		"",
		projectSearchQuery,
		repository,
		namespace,
		queueFolder,
		maxArtifactSize,
		artifacts,
		false,
		false,
		truffleHogVerification,
		jobLimit,
		threads,
		confidenceFilter,
		hitTimeout,
	)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed initializing public scan options")
	}

	scanner := gitlabscan.NewScanner(scanOpts)
	logging.RegisterStatusHook(func() *zerolog.Event {
		queueLength := scanner.GetQueueStatus()
		return log.Info().Int("pendingjobs", queueLength)
	})

	if err := scanner.Scan(); err != nil {
		log.Fatal().Err(err).Msg("Public scan failed")
	}
}
