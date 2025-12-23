package scan

import (
	"github.com/CompassSecurity/pipeleek/internal/cmd/flags"
	"github.com/CompassSecurity/pipeleek/pkg/config"
	giteascan "github.com/CompassSecurity/pipeleek/pkg/gitea/scan"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

type GiteaScanOptions struct {
	config.CommonScanOptions
	Organization string
	Repository   string
	Cookie       string
	RunsLimit    int
	StartRunID   int64
}

var scanOptions = GiteaScanOptions{
	CommonScanOptions: config.DefaultCommonScanOptions(),
}
var maxArtifactSize string

func NewScanCmd() *cobra.Command {
	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan Gitea Actions",
		Long: `Scan Gitea Actions workflow runs and artifacts for secrets
### Token Authentication

You can create a personal access token in Gitea by navigating to your user settings, selecting "Applications", and then "Generate New Token". 

### Cookie Authentication

Due to differences between Gitea Actions API and UI access rights validation, a session cookie may be required in some cases.
The Actions API and UI are not yet fully in sync, causing some repositories to return 403 errors via API even when accessible through the UI.

To obtain the cookie:
1. Open your Gitea instance in a web browser
2. Open Developer Tools (F12)
3. Navigate to Application/Storage > Cookies
4. Find and copy the value of the 'i_like_gitea' cookie
5. Use it with the --cookie flag
`,
		Example: `
# Scan all accessible repositories (including public) and their artifacts
pipeleek gitea scan --token gitea_token_xxxxx --gitea https://gitea.example.com --artifacts --cookie your_cookie_value

# Scan without downloading artifacts
pipeleek gitea scan --token gitea_token_xxxxx --gitea https://gitea.example.com --cookie your_cookie_value

# Scan only repositories owned by the user
pipeleek gitea scan --token gitea_token_xxxxx --gitea https://gitea.example.com --owned --cookie your_cookie_value

# Scan all repositories of a specific organization
pipeleek gitea scan --token gitea_token_xxxxx --gitea https://gitea.example.com --organization my-org --cookie your_cookie_value

# Scan a specific repository
pipeleek gitea scan --token gitea_token_xxxxx --gitea https://gitea.example.com --repository owner/repo-name --cookie your_cookie_value

# Scan a specific repository but limit the number of workflow runs to scan
pipeleek gitea scan --token gitea_token_xxxxx --gitea https://gitea.example.com --repository owner/repo-name --runs-limit 20 --cookie your_cookie_value
		`,
		Run: Scan,
	}

	flags.AddCommonScanFlags(scanCmd, &scanOptions.CommonScanOptions, &maxArtifactSize)
	scanCmd.Flags().StringVarP(&scanOptions.Organization, "organization", "", "", "Scan all repositories of a specific organization")
	scanCmd.Flags().StringVarP(&scanOptions.Repository, "repository", "r", "", "Scan a specific repository (format: owner/repo)")
	scanCmd.Flags().StringVarP(&scanOptions.Cookie, "cookie", "c", "", "Gitea session cookie (i_like_gitea). Needed when scanning where you are NOT the owner of the repository")
	scanCmd.Flags().IntVarP(&scanOptions.RunsLimit, "runs-limit", "", 0, "Limit the number of workflow runs to scan per repository (0 = unlimited)")
	scanCmd.Flags().Int64VarP(&scanOptions.StartRunID, "start-run-id", "", 0, "Start scanning from a specific run ID (only valid with --repository flag, 0 = start from latest)")

	return scanCmd
}

func Scan(cmd *cobra.Command, args []string) {
	if err := config.AutoBindFlags(cmd, map[string]string{
		"gitea":                    "gitea.url",
		"token":                    "gitea.token",
		"cookie":                   "gitea.cookie",
		"threads":                  "common.threads",
		"truffle-hog-verification": "common.trufflehog_verification",
		"max-artifact-size":        "common.max_artifact_size",
		"confidence":               "common.confidence_filter",
		"hit-timeout":              "common.hit_timeout",
	}); err != nil {
		log.Fatal().Err(err).Msg("Failed to bind command flags to configuration keys")
	}

	if err := config.RequireConfigKeys("gitea.url", "gitea.token"); err != nil {
		log.Fatal().Err(err).Msg("Missing required configuration")
	}

	giteaURL := config.GetString("gitea.url")
	giteaToken := config.GetString("gitea.token")
	scanOptions.Cookie = config.GetString("gitea.cookie")
	scanOptions.MaxScanGoRoutines = config.GetInt("common.threads")
	scanOptions.TruffleHogVerification = config.GetBool("common.trufflehog_verification")
	maxArtifactSize = config.GetString("common.max_artifact_size")
	scanOptions.ConfidenceFilter = config.GetStringSlice("common.confidence_filter")

	if scanOptions.StartRunID > 0 && scanOptions.Repository == "" {
		log.Fatal().Msg("--start-run-id can only be used with --repository flag")
	}

	if err := config.ValidateURL(giteaURL, "Gitea URL"); err != nil {
		log.Fatal().Err(err).Msg("Invalid Gitea URL")
	}
	if err := config.ValidateToken(giteaToken, "Gitea Access Token"); err != nil {
		log.Fatal().Err(err).Msg("Invalid Gitea Access Token")
	}
	if err := config.ValidateThreadCount(scanOptions.MaxScanGoRoutines); err != nil {
		log.Fatal().Err(err).Msg("Invalid thread count")
	}

	scanOpts, err := giteascan.InitializeOptions(
		giteaToken,
		giteaURL,
		scanOptions.Repository,
		scanOptions.Organization,
		scanOptions.Cookie,
		maxArtifactSize,
		scanOptions.Owned,
		scanOptions.Artifacts,
		scanOptions.TruffleHogVerification,
		scanOptions.RunsLimit,
		scanOptions.StartRunID,
		scanOptions.MaxScanGoRoutines,
		scanOptions.ConfidenceFilter,
		scanOptions.HitTimeout,
	)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed initializing scan options")
	}

	if scanOptions.Cookie != "" {
		if err := giteascan.ValidateCookie(scanOpts); err != nil {
			log.Fatal().Err(err).Msg("Cookie validation failed")
		}
	}

	scanner := giteascan.NewScanner(scanOpts)
	if err := scanner.Scan(); err != nil {
		log.Fatal().Err(err).Msg("Scan failed")
	}
}
