package scan

import (
	"github.com/CompassSecurity/pipeleek/internal/cmd/flags"
	"github.com/CompassSecurity/pipeleek/pkg/config"
	"github.com/CompassSecurity/pipeleek/pkg/gitlab/scan"
	"github.com/CompassSecurity/pipeleek/pkg/logging"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

type ScanOptions struct {
	config.CommonScanOptions
	GitlabCookie       string
	ProjectSearchQuery string
	Member             bool
	Repository         string
	Namespace          string
	JobLimit           int
	QueueFolder        string
}

var options = ScanOptions{
	CommonScanOptions: config.DefaultCommonScanOptions(),
}
var maxArtifactSize string

func NewScanCmd() *cobra.Command {
	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan a GitLab instance",
		Long: `Scan a GitLab instance for secrets in pipeline jobs and optionally artifacts
### Dotenv
[Dotenv artifacts](https://docs.gitlab.com/ee/ci/yaml/artifacts_reports.html#artifactsreportsdotenv) are not accessible through the GitLab API. To scan these, you need to manually provide your session cookie after logging in via a web browser. The session cookie name is _gitlab_session. The cookie should be valid for [two weeks](https://gitlab.com/gitlab-org/gitlab/-/issues/395038).

### Memory Usage

As the scanner processes a lot of resources (especially when using  --artifacts) memory, CPU and disk usage can become hard to manage.
You can tweak --threads, --max-artifact-size and --job-limit to obtain a customized performance and achieve stable processing.
`,
		Example: `
# Scan all accessible projects pipelines and their artifacts and dotenv artifacts on gitlab.com
pipeleek gl scan --token glpat-xxxxxxxxxxx --gitlab https://gitlab.example.com -a -c [value-of-valid-_gitlab_session]

# Scan all projects matching the search query kubernetes
pipeleek gl scan --token glpat-xxxxxxxxxxx --gitlab https://gitlab.example.com --search kubernetes

# Scan all pipelines of projects you own
pipeleek gl scan --token glpat-xxxxxxxxxxx --gitlab https://gitlab.example.com --owned

# Scan all pipelines of projects you are a member of
pipeleek gl scan --token glpat-xxxxxxxxxxx --gitlab https://gitlab.example.com --member

# Scan all accessible projects pipelines but limit the number of jobs scanned per project to 10, only scan artifacts smaller than 200MB and use 8 threads
pipeleek gl scan --token glpat-xxxxxxxxxxx --gitlab https://gitlab.example.com --job-limit 10 -a --max-artifact-size 200Mb --threads 8

# Scan a single repository
pipeleek gl scan --token glpat-xxxxxxxxxxx --gitlab https://gitlab.example.com --repo mygroup/myproject

# Scan all repositories in a namespace
pipeleek gl scan --token glpat-xxxxxxxxxxx --gitlab https://gitlab.example.com --namespace mygroup
		`,
		Run: Scan,
	}

	flags.AddCommonScanFlags(scanCmd, &options.CommonScanOptions, &maxArtifactSize)
	scanCmd.Flags().StringVarP(&options.GitlabCookie, "cookie", "c", "", "GitLab Cookie _gitlab_session (must be extracted from your browser, use remember me)")
	scanCmd.Flags().StringVarP(&options.ProjectSearchQuery, "search", "s", "", "Query string for searching projects")
	scanCmd.Flags().BoolVarP(&options.Member, "member", "m", false, "Scan projects the user is member of")
	scanCmd.Flags().StringVarP(&options.Repository, "repo", "r", "", "Single repository to scan, format: namespace/repo")
	scanCmd.Flags().StringVarP(&options.Namespace, "namespace", "n", "", "Namespace to scan (all repos in the namespace will be scanned)")
	scanCmd.Flags().IntVarP(&options.JobLimit, "job-limit", "j", 0, "Scan a max number of pipeline jobs - trade speed vs coverage. 0 scans all and is the default.")
	scanCmd.Flags().StringVarP(&options.QueueFolder, "queue", "q", "", "Relative or absolute folderpath where the queue files will be stored. Defaults to system tmp. Non-existing folders will be created.")

	return scanCmd
}

func Scan(cmd *cobra.Command, args []string) {
	// Bind flags to Viper configuration keys for automatic priority handling
	if err := config.BindFlags(cmd, map[string]string{
		"gitlab":                  "gitlab.url",
		"token":                   "gitlab.token",
		"cookie":                  "gitlab.cookie",
		"threads":                 "common.threads",
		"truffle-hog-verification": "common.trufflehog_verification",
		"max-artifact-size":       "common.max_artifact_size",
		"confidence":              "common.confidence_filter",
	}); err != nil {
		log.Fatal().Err(err).Msg("Failed to bind flags")
	}

	// Get values using Viper (automatic priority: CLI flags > config file > defaults)
	gitlabUrl := config.GetString("gitlab.url")
	gitlabApiToken := config.GetString("gitlab.token")
	options.GitlabCookie = config.GetString("gitlab.cookie")
	options.MaxScanGoRoutines = config.GetInt("common.threads")
	options.TruffleHogVerification = config.GetBool("common.trufflehog_verification")
	maxArtifactSize = config.GetString("common.max_artifact_size")
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

	scanOpts, err := scan.InitializeOptions(
		gitlabUrl,
		gitlabApiToken,
		options.GitlabCookie,
		options.ProjectSearchQuery,
		options.Repository,
		options.Namespace,
		options.QueueFolder,
		maxArtifactSize,
		options.Artifacts,
		options.Owned,
		options.Member,
		options.TruffleHogVerification,
		options.JobLimit,
		options.MaxScanGoRoutines,
		options.ConfidenceFilter,
		options.HitTimeout,
	)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed initializing scan options")
	}

	scanner := scan.NewScanner(scanOpts)
	logging.RegisterStatusHook(func() *zerolog.Event {
		queueLength := scanner.GetQueueStatus()
		return log.Info().Int("pendingjobs", queueLength)
	})

	if err := scanner.Scan(); err != nil {
		log.Fatal().Err(err).Msg("Scan failed")
	}
}
