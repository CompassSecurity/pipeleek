package scan

import (
	"fmt"
	"time"

	"github.com/CompassSecurity/pipeleek/internal/cmd/flags"
	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkgscan "github.com/CompassSecurity/pipeleek/pkg/devops/scan"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

type DevOpsScanOptions struct {
	config.CommonScanOptions
	Username     string
	AccessToken  string
	MaxBuilds    int
	Organization string
	Project      string
	DevOpsURL    string
}

var options = DevOpsScanOptions{
	CommonScanOptions: config.DefaultCommonScanOptions(),
}
var maxArtifactSize string
var flagBindings = map[string]string{
	"devops":                   "azure_devops.url",
	"token":                    "azure_devops.token",
	"username":                 "azure_devops.username",
	"organization":             "azure_devops.scan.organization",
	"project":                  "azure_devops.scan.project",
	"max-builds":               "azure_devops.scan.max_builds",
	"artifacts":                "azure_devops.scan.artifacts",
	"owned":                    "azure_devops.scan.owned",
	"threads":                  "common.threads",
	"truffle-hog-verification": "common.trufflehog_verification",
	"max-artifact-size":        "common.max_artifact_size",
	"confidence":               "common.confidence_filter",
	"hit-timeout":              "common.hit_timeout",
}

func NewScanCmd() *cobra.Command {
	scanCmd := &cobra.Command{
		Use:   "scan [no options!]",
		Short: "Scan Azure DevOps Actions",
		Long: `Scan Azure DevOps pipelines for secrets in logs and artifacts.

### Authentication
Create your personal access token here: https://dev.azure.com/{yourproject}/_usersSettings/tokens

> In the top right corner you can choose the scope (Global, Project etc.). 
> Global in that case means per tenant. If you have access to multiple tentants you need to run a scan per tenant.
> Create a read-only token with all scopes (click show all scopes), select the correct organization(s) and then generate the token.
> Get you username from an HTTPS git clone url from the UI.
		`,
		Example: `
# Scan all pipelines the current user has access to
pipeleek ad scan --token <azdo_pat> --username auser --artifacts

# Scan all pipelines of an organization
pipeleek ad scan --token <azdo_pat> --username auser --artifacts --organization myOrganization

# Scan all pipelines of a project e.g. https://dev.azure.com/PowerShell/PowerShell
pipeleek ad scan --token <azdo_pat> --username auser --artifacts --organization powershell --project PowerShell
		`,
		Run: Scan,
	}
	flags.AddCommonScanFlags(scanCmd, &options.CommonScanOptions, &maxArtifactSize)

	scanCmd.Flags().StringVarP(&options.AccessToken, "token", "t", "", "Azure DevOps Personal Access Token - https://dev.azure.com/{yourUsername}/_usersSettings/tokens")
	scanCmd.Flags().StringVarP(&options.Username, "username", "u", "", "Username")

	scanCmd.Flags().IntVarP(&options.MaxBuilds, "max-builds", "", -1, "Max. number of builds to scan per project")
	scanCmd.Flags().StringVarP(&options.Organization, "organization", "", "", "Organization name to scan")
	scanCmd.Flags().StringVarP(&options.Project, "project", "p", "", "Project name to scan - can be combined with organization")
	scanCmd.Flags().StringVarP(&options.DevOpsURL, "devops", "d", "https://dev.azure.com", "Azure DevOps base URL")

	return scanCmd
}

func Scan(cmd *cobra.Command, args []string) {
	// #nosec G101 -- "token" is a configuration key name, not a hardcoded credential
	// Unified command setup with flag binding, required key validation, and validators
	config.NewCommandSetup(cmd).
		WithFlagBindings(flagBindings).
		RequireKeys("azure_devops.token", "azure_devops.username").
		AddValidator(func() error { return config.ValidateURL(config.GetString("azure_devops.url"), "Azure DevOps URL") }).
		AddValidator(func() error { return config.ValidateToken(config.GetString("azure_devops.token"), "Azure DevOps Access Token") }).
		AddValidator(func() error { return config.ValidateThreadCount(config.GetInt("common.threads")) }).
		MustBind()

	// Load configuration values
	options.DevOpsURL = config.GetString("azure_devops.url")
	options.AccessToken = config.GetString("azure_devops.token")
	options.Username = config.GetString("azure_devops.username")
	options.Organization = config.GetString("azure_devops.scan.organization")
	options.Project = config.GetString("azure_devops.scan.project")
	options.MaxBuilds = config.GetInt("azure_devops.scan.max_builds")
	options.Artifacts = config.GetBool("azure_devops.scan.artifacts")
	options.Owned = config.GetBool("azure_devops.scan.owned")
	options.MaxScanGoRoutines = config.GetInt("common.threads")
	options.TruffleHogVerification = config.GetBool("common.trufflehog_verification")
	maxArtifactSize = config.GetString("common.max_artifact_size")
	options.ConfidenceFilter = config.GetStringSlice("common.confidence_filter")
	hitTimeoutRaw := config.GetString("common.hit_timeout")
	hitTimeout, err := time.ParseDuration(hitTimeoutRaw)
	if err != nil {
		log.Fatal().Err(fmt.Errorf("invalid hit-timeout %q: %w", hitTimeoutRaw, err)).Msg("Invalid hit timeout")
	}
	options.HitTimeout = hitTimeout

	scanOpts, err := pkgscan.InitializeOptions(
		options.Username,
		options.AccessToken,
		options.DevOpsURL,
		options.Organization,
		options.Project,
		maxArtifactSize,
		options.Artifacts,
		options.TruffleHogVerification,
		options.MaxBuilds,
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
