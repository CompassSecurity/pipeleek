package scan

import (
	"fmt"
	"strconv"
	"time"

	"github.com/CompassSecurity/pipeleek/internal/cmd/flags"
	"github.com/CompassSecurity/pipeleek/pkg/config"
	releasescan "github.com/CompassSecurity/pipeleek/pkg/gitlab/release/scan"
	"github.com/CompassSecurity/pipeleek/pkg/logging"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var flagBindings = map[string]string{
	"url": "gitlab.url", "token": "gitlab.token",
	"repo": "gitlab.release.scan.repo", "namespace": "gitlab.release.scan.namespace",
	"search": "gitlab.release.scan.search", "owned": "gitlab.release.scan.owned",
	"member": "gitlab.release.scan.member", "tag": "gitlab.release.scan.tag",
	"release-limit": "gitlab.release.scan.release_limit", "include-sources": "gitlab.release.scan.include_sources",
	"max-artifact-size": "common.max_artifact_size", "threads": "common.threads",
	"secrets-verification": "common.secrets_verification", "confidence": "common.confidence_filter",
	"hit-timeout": "common.hit_timeout", "webui": "common.webui",
}

func NewScanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use: "scan", Short: "Scan GitLab release assets for secrets",
		Long: `Scan linked assets of published GitLab releases for secrets.
By default, scan all releases of all token-visible projects, including HTTP(S)
assets hosted outside GitLab. GitLab credentials are never sent to other origins.
Use --include-sources to also scan one generated source ZIP per release.

Assets exceeding --max-artifact-size (downloaded bytes) are skipped.
Extracted archive sizes are not limited.
Other coverage failures are reported while scanning continues, with a nonzero exit.
--member applies to global project discovery; --owned and --search also apply
within --namespace, including subgroups. --repo takes precedence over list filters.`,
		Example: `# Scan all visible projects' release assets
pipeleek gl release scan --url https://gitlab.example.com --token [redacted]

# Scan one release, including its generated source ZIP
pipeleek gl release scan --url https://gitlab.example.com --token [redacted] --repo group/project --tag v1.0 --include-sources

# Scan the newest five published releases per project in a namespace
pipeleek gl release scan --url https://gitlab.example.com --token [redacted] --namespace group --release-limit 5`,
		Args: cobra.NoArgs, Run: Scan,
	}
	common := config.DefaultCommonScanOptions()
	flags.AddCommonScanFlagsNoArtifacts(cmd, &common)
	cmd.Flags().String("max-artifact-size", "500Mb", "Maximum downloaded bytes per asset; extracted archive sizes are not limited")
	cmd.Flags().StringP("repo", "r", "", "Single repository to scan, format: namespace/repo")
	cmd.Flags().StringP("namespace", "n", "", "Namespace to scan, including subgroup projects")
	cmd.Flags().StringP("search", "s", "", "Query string for searching projects")
	cmd.Flags().BoolP("owned", "o", false, "Scan only user owned repositories")
	cmd.Flags().BoolP("member", "m", false, "Scan projects the user is a member of (global project discovery)")
	cmd.Flags().String("tag", "", "Exact release tag to scan (requires --repo)")
	cmd.Flags().Int("release-limit", 0, "Maximum published releases per project, newest first; 0 scans all")
	cmd.Flags().Bool("include-sources", false, "Also scan one generated source ZIP per release")
	return cmd
}

func optionsFromConfig() (releasescan.Options, error) {
	maxBytes, err := config.ParseMaxArtifactSize(config.GetString("common.max_artifact_size"))
	if err != nil {
		return releasescan.Options{}, err
	}
	rawTimeout := config.GetString("common.hit_timeout")
	if _, err := strconv.ParseInt(rawTimeout, 10, 64); err == nil {
		rawTimeout += "s"
	}
	timeout, err := time.ParseDuration(rawTimeout)
	if err != nil {
		return releasescan.Options{}, fmt.Errorf("invalid hit-timeout: %w", err)
	}
	o := releasescan.Options{
		URL: config.GetString("gitlab.url"), Token: config.GetString("gitlab.token"),
		Repo: config.GetString("gitlab.release.scan.repo"), Namespace: config.GetString("gitlab.release.scan.namespace"),
		Search: config.GetString("gitlab.release.scan.search"), Owned: config.GetBool("gitlab.release.scan.owned"),
		Member: config.GetBool("gitlab.release.scan.member"), Tag: config.GetString("gitlab.release.scan.tag"),
		ReleaseLimit:   config.GetInt("gitlab.release.scan.release_limit"),
		IncludeSources: config.GetBool("gitlab.release.scan.include_sources"),
		MaxBytes:       maxBytes, Threads: config.GetInt("common.threads"),
		SecretsVerification: config.GetBool("common.secrets_verification"),
		Confidence:          config.GetStringSlice("common.confidence_filter"), HitTimeout: timeout,
	}
	return o, o.Validate()
}

func Scan(cmd *cobra.Command, args []string) {
	config.NewCommandSetup(cmd).WithFlagBindings(flagBindings).
		RequireKeys("gitlab.url", "gitlab.token").MustBind()
	opts, err := optionsFromConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("Invalid release scan configuration")
	}
	ui := flags.StartScanWebUI(cmd, opts.URL, flagBindings)
	if ui != nil {
		defer ui.Close()
	}
	s := releasescan.NewScanner(opts)
	logging.RegisterStatusHook(s.Status)
	err = s.Scan()
	if ui != nil {
		if err == nil {
			ui.Wait()
		} else {
			_ = ui.Close()
		}
	}
	if err != nil {
		log.Fatal().Err(err).Msg("Release scan failed")
	}
}
