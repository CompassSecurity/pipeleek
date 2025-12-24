package scan

import (
	"github.com/CompassSecurity/pipeleek/internal/cmd/flags"
	pkgscan "github.com/CompassSecurity/pipeleek/pkg/bitbucket/scan"
	"github.com/CompassSecurity/pipeleek/pkg/config"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

type BitBucketScanOptions struct {
	config.CommonScanOptions
	Email           string
	AccessToken     string
	MaxPipelines    int
	Workspace       string
	Public          bool
	After           string
	BitBucketURL    string
	BitBucketCookie string
}

var options = BitBucketScanOptions{
	CommonScanOptions: config.DefaultCommonScanOptions(),
}
var maxArtifactSize string

func NewScanCmd() *cobra.Command {
	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan BitBucket Pipelines",
		Long: `Create a BitBucket scoped API token [here](https://id.atlassian.com/manage-profile/security/api-tokens) and pass it to the <code>--token</code> flag.
The <code>--email</code> flag expects your account's email address.
To scan artifacts (uses internal APIs) you need to extract the session cookie value <code>cloud.session.token</code> from [bitbucket.org](https://bitbucket.org) using your browser and supply it in the <code>--cookie</code> flag.
A note on artifacts: Bitbucket artifacts are only stored for a limited time and only for paid accounts. Free accounts might not have artifacts available at all.
		  `,
		Example: `
# Scan a workspace (find public ones here: https://bitbucket.org/repo/all/) without artifacts
pipeleek bb scan --token ATATTxxxxxx --email auser@example.com --workspace bitbucketpipelines

# Scan your owned repositories and their artifacts
pipeleek bb scan -t ATATTxxxxxx -c eyJxxxxxxxxxxx --artifacts -e auser@example.com --owned

# Scan all public repositories without their artifacts
> If using --after, the API becomes quite unreliable 👀
pipeleek bb scan --token ATATTxxxxxx --email auser@example.com --public --maxPipelines 5 --after 2025-03-01T15:00:00+00:00
		`,
		Run: Scan,
	}
	flags.AddCommonScanFlags(scanCmd, &options.CommonScanOptions, &maxArtifactSize)

	scanCmd.Flags().StringVarP(&options.AccessToken, "token", "t", "", "Bitbucket API token - https://id.atlassian.com/manage-profile/security/api-tokens")
	scanCmd.Flags().StringVarP(&options.Email, "email", "e", "", "Bitbucket Email")
	scanCmd.Flags().StringVarP(&options.BitBucketCookie, "cookie", "c", "", "Bitbucket Cookie [value of cloud.session.token on https://bitbucket.org]")
	scanCmd.Flags().StringVarP(&options.BitBucketURL, "bitbucket", "b", "https://api.bitbucket.org/2.0", "BitBucket API base URL")
	scanCmd.MarkFlagsRequiredTogether("cookie", "artifacts")

	scanCmd.Flags().IntVarP(&options.MaxPipelines, "max-pipelines", "", -1, "Max. number of pipelines to scan per repository")
	scanCmd.Flags().StringVarP(&options.Workspace, "workspace", "w", "", "Workspace name to scan")
	scanCmd.Flags().BoolVarP(&options.Public, "public", "p", false, "Scan all public repositories")
	scanCmd.Flags().StringVarP(&options.After, "after", "", "", "Filter public repos by a given date in ISO 8601 format: 2025-04-02T15:00:00+02:00 ")

	return scanCmd
}

func Scan(cmd *cobra.Command, args []string) {
	if err := config.AutoBindFlags(cmd, map[string]string{
		"bitbucket":                "bitbucket.url",
		"token":                    "bitbucket.token",
		"email":                    "bitbucket.email",
		"cookie":                   "bitbucket.cookie",
		"threads":                  "common.threads",
		"truffle-hog-verification": "common.trufflehog_verification",
		"max-artifact-size":        "common.max_artifact_size",
		"confidence":               "common.confidence_filter",
		"hit-timeout":              "common.hit_timeout",
	}); err != nil {
		log.Fatal().Err(err).Msg("Failed to bind command flags to configuration keys")
	}

	options.BitBucketURL = config.GetString("bitbucket.url")
	options.AccessToken = config.GetString("bitbucket.token")
	options.Email = config.GetString("bitbucket.email")
	options.BitBucketCookie = config.GetString("bitbucket.cookie")
	options.MaxScanGoRoutines = config.GetInt("common.threads")
	options.TruffleHogVerification = config.GetBool("common.trufflehog_verification")
	maxArtifactSize = config.GetString("common.max_artifact_size")
	options.ConfidenceFilter = config.GetStringSlice("common.confidence_filter")

	if options.AccessToken != "" && options.Email == "" {
		log.Fatal().Msg("When using --token you must also provide --email (or bitbucket.email in config)")
	}

	if err := config.ValidateURL(options.BitBucketURL, "BitBucket URL"); err != nil {
		log.Fatal().Err(err).Msg("Invalid BitBucket URL")
	}
	if options.AccessToken != "" {
		if err := config.ValidateToken(options.AccessToken, "BitBucket API Token"); err != nil {
			log.Fatal().Err(err).Msg("Invalid BitBucket API Token")
		}
	}
	if err := config.ValidateThreadCount(options.MaxScanGoRoutines); err != nil {
		log.Fatal().Err(err).Msg("Invalid thread count")
	}

	scanOpts, err := pkgscan.InitializeOptions(
		options.Email,
		options.AccessToken,
		options.BitBucketCookie,
		options.BitBucketURL,
		options.Workspace,
		options.After,
		maxArtifactSize,
		options.Owned,
		options.Public,
		options.Artifacts,
		options.TruffleHogVerification,
		options.MaxPipelines,
		options.MaxScanGoRoutines,
		options.ConfidenceFilter,
		options.HitTimeout,
	)
	if err != nil {
		log.Fatal().Err(err).Str("size", maxArtifactSize).Msg("Failed parsing max-artifact-size flag")
	}

	scanner := pkgscan.NewScanner(scanOpts)
	if err := scanner.Scan(); err != nil {
		log.Fatal().Err(err).Msg("Scan failed")
	}
}
