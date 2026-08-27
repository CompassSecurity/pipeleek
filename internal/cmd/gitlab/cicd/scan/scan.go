package scan

import (
	"github.com/CompassSecurity/pipeleek/internal/cmd/flags"
	"github.com/CompassSecurity/pipeleek/pkg/config"
	"github.com/CompassSecurity/pipeleek/pkg/gitlab/scan"
	"github.com/CompassSecurity/pipeleek/pkg/logging"
	"github.com/CompassSecurity/pipeleek/pkg/scanner/detectors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

type ScanOptions struct {
	config.CommonScanOptions
	ProjectSearchQuery string
	Member             bool
	Repository         string
	Namespace          string
	QueueFolder        string
}

var options = ScanOptions{
	CommonScanOptions: config.DefaultCommonScanOptions(),
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

	flags.AddCommonScanFlagsNoArtifacts(scanCmd, &options.CommonScanOptions)
	scanCmd.Flags().BoolVarP(&options.Owned, "owned", "o", false, "Scan only user owned repositories")
	scanCmd.Flags().StringVarP(&options.ProjectSearchQuery, "search", "s", "", "Query string for searching projects")
	scanCmd.Flags().BoolVarP(&options.Member, "member", "m", false, "Scan projects the user is member of")
	scanCmd.Flags().StringVarP(&options.Repository, "repo", "r", "", "Single repository to scan, format: namespace/repo")
	scanCmd.Flags().StringVarP(&options.Namespace, "namespace", "n", "", "Namespace to scan (all repos in the namespace will be scanned)")
	scanCmd.Flags().StringVarP(&options.QueueFolder, "queue", "q", "", "Relative or absolute folderpath where the queue files will be stored. Defaults to system tmp. Non-existing folders will be created.")

	return scanCmd
}

func Scan(cmd *cobra.Command, args []string) {
	config.NewCommandSetup(cmd).
		WithFlagBindings(flagBindings).
		RequireKeys("gitlab.url", "gitlab.token").
		MustBind()

	gitlabUrl := config.GetString("gitlab.url")
	gitlabApiToken := config.GetString("gitlab.token")
	options.ProjectSearchQuery = config.GetString("gitlab.cicd.scan.search")
	options.Member = config.GetBool("gitlab.cicd.scan.member")
	options.Repository = config.GetString("gitlab.cicd.scan.repo")
	options.Namespace = config.GetString("gitlab.cicd.scan.namespace")
	options.Owned = config.GetBool("gitlab.cicd.scan.owned")
	options.QueueFolder = config.GetString("gitlab.cicd.scan.queue")
	options.MaxScanGoRoutines = config.GetInt("common.threads")
	options.TruffleHogVerification = config.GetBool("common.trufflehog_verification")
	options.ConfidenceFilter = config.GetStringSlice("common.confidence_filter")

	if err := config.ValidateURL(gitlabUrl, "GitLab URL"); err != nil {
		log.Fatal().Err(err).Msg("Invalid GitLab URL")
	}
	if err := config.ValidateToken(gitlabApiToken, "GitLab API Token"); err != nil {
		log.Fatal().Err(err).Msg("Invalid GitLab API Token")
	}
	if err := config.ValidateThreadCount(options.MaxScanGoRoutines); err != nil {
		log.Fatal().Err(err).Msg("Invalid thread count")
	}

	detectors.SetGitLabURL(gitlabUrl)

	scanOpts, err := scan.InitializeOptions(
		gitlabUrl,
		gitlabApiToken,
		"",
		options.ProjectSearchQuery,
		options.Repository,
		options.Namespace,
		options.QueueFolder,
		"0",
		false,
		options.Owned,
		options.Member,
		options.TruffleHogVerification,
		0,
		options.MaxScanGoRoutines,
		options.ConfidenceFilter,
		options.HitTimeout,
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
