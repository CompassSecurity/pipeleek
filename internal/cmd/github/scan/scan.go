package scan

import (
	"github.com/CompassSecurity/pipeleek/internal/cmd/flags"
	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgscan "github.com/CompassSecurity/pipeleek/pkg/github/scan"
	"github.com/CompassSecurity/pipeleek/pkg/logging"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

type GitHubScanOptions struct {
	config.CommonScanOptions
	AccessToken  string
	MaxWorkflows int
	Organization string
	User         string
	Public       bool
	SearchQuery  string
	GitHubURL    string
	Repo         string
}

var options = GitHubScanOptions{
	CommonScanOptions: config.DefaultCommonScanOptions(),
}
var maxArtifactSize string

func NewScanCmd() *cobra.Command {
	scanCmd := &cobra.Command{
		Use:   "scan [no options!]",
		Short: "Scan GitHub Actions",
		Long:  `Scan GitHub Actions workflow runs and artifacts for secrets`,
		Example: `
# Scan owned repositories including their artifacts
pipeleek gh scan --token github_pat_xxxxxxxxxxx --artifacts --owned

# Scan repositories of an organization
pipeleek gh scan --token github_pat_xxxxxxxxxxx --artifacts --maxWorkflows 10 --org apache

# Scan public repositories
pipeleek gh scan --token github_pat_xxxxxxxxxxx --artifacts --maxWorkflows 10 --public

# Scan by search term
pipeleek gh scan --token github_pat_xxxxxxxxxxx --artifacts --maxWorkflows 10 --search iac

# Scan repositories of a user
pipeleek gh scan --token github_pat_xxxxxxxxxxx --artifacts --user firefart

# Scan a single repository
pipeleek gh scan --token github_pat_xxxxxxxxxxx --artifacts --repo owner/repo
		`,
		Run: Scan,
	}
	flags.AddCommonScanFlags(scanCmd, &options.CommonScanOptions, &maxArtifactSize)

	scanCmd.Flags().StringVarP(&options.AccessToken, "token", "t", "", "GitHub Personal Access Token - https://github.com/settings/tokens")
	err := scanCmd.MarkFlagRequired("token")
	if err != nil {
		log.Fatal().Msg("Unable to require token flag")
	}

	scanCmd.Flags().IntVarP(&options.MaxWorkflows, "max-workflows", "", -1, "Max. number of workflows to scan per repository")
	scanCmd.Flags().StringVarP(&options.Organization, "org", "", "", "GitHub organization name to scan")
	scanCmd.Flags().StringVarP(&options.User, "user", "", "", "GitHub user name to scan")
	scanCmd.Flags().BoolVarP(&options.Public, "public", "p", false, "Scan all public repositories")
	scanCmd.Flags().StringVarP(&options.SearchQuery, "search", "s", "", "GitHub search query")
	scanCmd.Flags().StringVarP(&options.Repo, "repo", "r", "", "Scan a single repository in the format owner/repo")
	scanCmd.Flags().StringVarP(&options.GitHubURL, "github", "g", "https://api.github.com", "GitHub API base URL")
	scanCmd.MarkFlagsMutuallyExclusive("owned", "org", "user", "public", "search", "repo")

	return scanCmd
}

func Scan(cmd *cobra.Command, args []string) {
	// Apply config file values to common scan options
	flags.ApplyConfigToCommonScanOptions(cmd, &options.CommonScanOptions, &maxArtifactSize)

	// Get values with priority: CLI flag > config file > default
	githubURL := config.GetStringValue(cmd, "github", func(c *config.Config) string { return c.GitHub.URL })
	accessToken := config.GetStringValue(cmd, "token", func(c *config.Config) string { return c.GitHub.Token })
	
	// Update options with config-aware values
	if githubURL != "" {
		options.GitHubURL = githubURL
	}
	if accessToken != "" {
		options.AccessToken = accessToken
	}

	if err := config.ValidateURL(options.GitHubURL, "GitHub URL"); err != nil {
		log.Fatal().Err(err).Msg("Invalid GitHub URL")
	}
	if err := config.ValidateToken(options.AccessToken, "GitHub Access Token"); err != nil {
		log.Fatal().Err(err).Msg("Invalid GitHub Access Token")
	}
	if err := config.ValidateThreadCount(options.MaxScanGoRoutines); err != nil {
		log.Fatal().Err(err).Msg("Invalid thread count")
	}

	scanOpts, err := pkgscan.InitializeOptions(
		options.AccessToken,
		options.GitHubURL,
		options.Repo,
		options.Organization,
		options.User,
		options.SearchQuery,
		maxArtifactSize,
		options.Owned,
		options.Public,
		options.Artifacts,
		options.TruffleHogVerification,
		options.MaxWorkflows,
		options.MaxScanGoRoutines,
		options.ConfidenceFilter,
		options.HitTimeout,
	)
	if err != nil {
		log.Fatal().Err(err).Str("size", maxArtifactSize).Msg("Failed parsing max-artifact-size flag")
	}

	scanner := pkgscan.NewScanner(scanOpts)
	logging.RegisterStatusHook(func() *zerolog.Event { return scanner.GetRateLimitStatus() })

	if err := scanner.Scan(); err != nil {
		log.Fatal().Err(err).Msg("Scan failed")
	}
}
