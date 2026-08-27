package scan

import (
	"fmt"
	"time"

	"github.com/CompassSecurity/pipeleek/internal/cmd/flags"
	"github.com/CompassSecurity/pipeleek/pkg/config"
	"github.com/CompassSecurity/pipeleek/pkg/gitlab/scan"
	"github.com/CompassSecurity/pipeleek/pkg/logging"
	"github.com/CompassSecurity/pipeleek/pkg/scanner/detectors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// scanOptions collects the resolved config values for a single run of the command.
type scanOptions struct {
	config.CommonScanOptions
	GitlabUrl          string
	GitlabApiToken     string
	ProjectSearchQuery string
	Member             bool
	Repository         string
	Namespace          string
	QueueFolder        string
}

// flagBindings maps CLI flags to configuration keys for binding and testing
var flagBindings = map[string]string{
	"url":                      "gitlab.url",
	"token":                    "gitlab.token",
	"search":                   "gitlab.cicd.scan.search",
	"member":                   "gitlab.cicd.scan.member",
	"repo":                     "gitlab.cicd.scan.repo",
	"namespace":                "gitlab.cicd.scan.namespace",
	"owned":                    "gitlab.cicd.scan.owned",
	"queue":                    "gitlab.cicd.scan.queue",
	"threads":                  "common.threads",
	"truffle-hog-verification": "common.trufflehog_verification",
	"confidence":               "common.confidence_filter",
	"hit-timeout":              "common.hit_timeout",
}

func NewScanCmd() *cobra.Command {
	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan CI/CD YAML configurations for secrets",
		Long: `Scan the fully compiled .gitlab-ci.yml configuration of accessible projects for secrets.

Unlike "gl scan", this command only fetches and scans each project's merged CI/CD YAML - it does not scan job logs or artifacts.`,
		Example: `
# Scan the CI/CD YAML of all accessible projects
pipeleek gl cicd scan --token glpat-xxxxxxxxxxx --url https://gitlab.example.com

# Scan a single repository
pipeleek gl cicd scan --token glpat-xxxxxxxxxxx --url https://gitlab.example.com --repo mygroup/myproject

# Scan all repositories in a namespace
pipeleek gl cicd scan --token glpat-xxxxxxxxxxx --url https://gitlab.example.com --namespace mygroup
		`,
		Run: Scan,
	}

	defaultOpts := config.DefaultCommonScanOptions()
	flags.AddCommonScanFlagsNoArtifacts(scanCmd, &defaultOpts)
	scanCmd.Flags().BoolP("owned", "o", false, "Scan only user owned repositories")
	scanCmd.Flags().StringP("search", "s", "", "Query string for searching projects")
	scanCmd.Flags().BoolP("member", "m", false, "Scan projects the user is member of")
	scanCmd.Flags().StringP("repo", "r", "", "Single repository to scan, format: namespace/repo")
	scanCmd.Flags().StringP("namespace", "n", "", "Namespace to scan (all repos in the namespace will be scanned)")
	scanCmd.Flags().StringP("queue", "q", "", "Relative or absolute folderpath where the queue files will be stored. Defaults to system tmp. Non-existing folders will be created.")

	return scanCmd
}

// Scan is the named Cobra Run handler; it resolves config into a local options struct and delegates to runScan.
func Scan(cmd *cobra.Command, args []string) {
	config.NewCommandSetup(cmd).
		WithFlagBindings(flagBindings).
		RequireKeys("gitlab.url", "gitlab.token").
		MustBind()

	hitTimeoutRaw := config.GetString("common.hit_timeout")
	hitTimeout, err := time.ParseDuration(hitTimeoutRaw)
	if err != nil {
		log.Fatal().Err(fmt.Errorf("invalid hit-timeout %q: %w", hitTimeoutRaw, err)).Msg("Invalid hit timeout")
	}

	opts := scanOptions{
		GitlabUrl:          config.GetString("gitlab.url"),
		GitlabApiToken:     config.GetString("gitlab.token"),
		ProjectSearchQuery: config.GetString("gitlab.cicd.scan.search"),
		Member:             config.GetBool("gitlab.cicd.scan.member"),
		Repository:         config.GetString("gitlab.cicd.scan.repo"),
		Namespace:          config.GetString("gitlab.cicd.scan.namespace"),
		QueueFolder:        config.GetString("gitlab.cicd.scan.queue"),
		CommonScanOptions: config.CommonScanOptions{
			Owned:                  config.GetBool("gitlab.cicd.scan.owned"),
			MaxScanGoRoutines:      config.GetInt("common.threads"),
			TruffleHogVerification: config.GetBool("common.trufflehog_verification"),
			ConfidenceFilter:       config.GetStringSlice("common.confidence_filter"),
			HitTimeout:             hitTimeout,
		},
	}

	runScan(opts)
}

func runScan(opts scanOptions) {
	if err := config.ValidateURL(opts.GitlabUrl, "GitLab URL"); err != nil {
		log.Fatal().Err(err).Msg("Invalid GitLab URL")
	}
	if err := config.ValidateToken(opts.GitlabApiToken, "GitLab API Token"); err != nil {
		log.Fatal().Err(err).Msg("Invalid GitLab API Token")
	}
	if err := config.ValidateThreadCount(opts.MaxScanGoRoutines); err != nil {
		log.Fatal().Err(err).Msg("Invalid thread count")
	}

	detectors.SetGitLabURL(opts.GitlabUrl)

	scanOpts, err := scan.InitializeOptions(
		opts.GitlabUrl,
		opts.GitlabApiToken,
		"",
		opts.ProjectSearchQuery,
		opts.Repository,
		opts.Namespace,
		opts.QueueFolder,
		"0",
		false,
		opts.Owned,
		opts.Member,
		opts.TruffleHogVerification,
		0,
		opts.MaxScanGoRoutines,
		opts.ConfidenceFilter,
		opts.HitTimeout,
	)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed initializing scan options")
	}
	scanOpts.CICDYamlOnly = true

	scanner := scan.NewScanner(scanOpts)
	logging.RegisterStatusHook(func() *zerolog.Event {
		queueLength := scanner.GetQueueStatus()
		return log.Info().Int("pendingYamlFiles", queueLength)
	})

	if err := scanner.Scan(); err != nil {
		log.Fatal().Err(err).Msg("Scan failed")
	}
}
