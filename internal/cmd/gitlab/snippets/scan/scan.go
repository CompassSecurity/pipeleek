package scan

import (
	"fmt"
	"time"

	"github.com/CompassSecurity/pipeleek/internal/cmd/flags"
	"github.com/CompassSecurity/pipeleek/pkg/config"
	snippetscan "github.com/CompassSecurity/pipeleek/pkg/gitlab/snippets/scan"
	"github.com/CompassSecurity/pipeleek/pkg/logging"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

type ScanOptions struct {
	config.CommonScanOptions
	Project            string
	Namespace          string
	ProjectSearchQuery string
	Member             bool
}

var options = ScanOptions{
	CommonScanOptions: config.DefaultCommonScanOptions(),
}

var flagBindings = map[string]string{
	"url":                      "gitlab.url",
	"token":                    "gitlab.token",
	"repo":                     "gitlab.snippets.scan.repo",
	"namespace":                "gitlab.snippets.scan.namespace",
	"search":                   "gitlab.snippets.scan.search",
	"owned":                    "gitlab.snippets.scan.owned",
	"member":                   "gitlab.snippets.scan.member",
	"threads":                  "common.threads",
	"truffle-hog-verification": "common.trufflehog_verification",
	"confidence":               "common.confidence_filter",
	"hit-timeout":              "common.hit_timeout",
}

func NewScanCmd() *cobra.Command {
	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan GitLab snippets for secrets",
		Long: `Scan snippet contents for secrets.

By default, all snippets visible to the provided token are scanned, including public ones.
Use --repo to limit to a single repository or --namespace to scan repositories in a namespace.`,
		Example: `
# Scan all snippets visible to the token
pipeleek gl snippets scan --token glpat-xxxxxxxxxxx --url https://gitlab.example.com

# Scan snippets for one repository
pipeleek gl snippets scan --token glpat-xxxxxxxxxxx --url https://gitlab.example.com --repo mygroup/myproject

# Scan snippets of repositories in a namespace
pipeleek gl snippets scan --token glpat-xxxxxxxxxxx --url https://gitlab.example.com --namespace mygroup
		`,
		Run: Scan,
	}

	flags.AddCommonScanFlagsNoArtifacts(scanCmd, &options.CommonScanOptions)
	scanCmd.Flags().BoolVarP(&options.Owned, "owned", "o", false, "Scan only user owned repositories")
	scanCmd.Flags().BoolVarP(&options.Member, "member", "m", false, "Scan projects the user is member of")
	scanCmd.Flags().StringVarP(&options.ProjectSearchQuery, "search", "s", "", "Query string for searching repositories")
	scanCmd.Flags().StringVarP(&options.Project, "repo", "r", "", "Single repository to scan, format: namespace/repo")
	scanCmd.Flags().StringVarP(&options.Namespace, "namespace", "n", "", "Namespace to scan (all namespace repositories and subgroup repositories)")

	return scanCmd
}

func Scan(cmd *cobra.Command, args []string) {
	config.NewCommandSetup(cmd).
		WithFlagBindings(flagBindings).
		RequireKeys("gitlab.url", "gitlab.token").
		AddValidator(func() error { return config.ValidateURL(config.GetString("gitlab.url"), "GitLab URL") }).
		AddValidator(func() error { return config.ValidateToken(config.GetString("gitlab.token"), "GitLab API Token") }).
		AddValidator(func() error { return config.ValidateThreadCount(config.GetInt("common.threads")) }).
		MustBind()

	gitlabURL := config.GetString("gitlab.url")
	gitlabToken := config.GetString("gitlab.token")
	project := config.GetString("gitlab.snippets.scan.repo")
	namespace := config.GetString("gitlab.snippets.scan.namespace")
	search := config.GetString("gitlab.snippets.scan.search")
	owned := config.GetBool("gitlab.snippets.scan.owned")
	member := config.GetBool("gitlab.snippets.scan.member")
	threads := config.GetInt("common.threads")
	truffleHogVerification := config.GetBool("common.trufflehog_verification")
	confidenceFilter := config.GetStringSlice("common.confidence_filter")
	hitTimeoutRaw := config.GetString("common.hit_timeout")
	hitTimeout, err := time.ParseDuration(hitTimeoutRaw)
	if err != nil {
		log.Fatal().Err(fmt.Errorf("invalid hit-timeout %q: %w", hitTimeoutRaw, err)).Msg("Invalid hit timeout")
	}

	if project != "" && namespace != "" {
		log.Fatal().Msg("--repo and --namespace are mutually exclusive")
	}

	opts, err := snippetscan.InitializeOptions(
		gitlabURL,
		gitlabToken,
		project,
		namespace,
		search,
		owned,
		member,
		threads,
		truffleHogVerification,
		confidenceFilter,
		hitTimeout,
	)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed initializing snippets scan options")
	}

	scanner := snippetscan.NewScanner(opts)
	logging.RegisterStatusHook(func() *zerolog.Event { return scanner.Status() })
	if err := scanner.Scan(); err != nil {
		log.Fatal().Err(err).Msg("Snippets scan failed")
	}
}
