package rules

import (
	"fmt"
	"strings"

	"github.com/CompassSecurity/pipeleek/pkg/config"
	scannerrules "github.com/CompassSecurity/pipeleek/pkg/scanner/rules"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func NewRulesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use: "rules", Short: "Manage optional secret-detection rules", GroupID: "Helper",
	}
	download := &cobra.Command{
		Use: "download", Short: "Download the optional Secrets Patterns Database stable rules",
		Long: "Download additional regex rules. These rules may substantially increase false positives and do not verify credentials.",
		Args: cobra.NoArgs, RunE: RunDownload, SilenceUsage: true,
	}
	download.Flags().String("output", "rules.yml", "Destination file (scans load rules.yml from the working directory)")
	download.Flags().Bool("force", false, "Replace an existing destination file")
	cmd.AddCommand(download)
	return cmd
}

func RunDownload(cmd *cobra.Command, args []string) error {
	config.NewCommandSetup(cmd).
		WithFlagBindings(map[string]string{
			"output": "rules.download.output",
			"force":  "rules.download.force",
		}).MustBind()
	opts := struct {
		output string
		force  bool
	}{
		output: config.GetString("rules.download.output"),
		force:  config.GetBool("rules.download.force"),
	}
	if strings.TrimSpace(opts.output) == "" {
		return fmt.Errorf("rules download output must not be empty")
	}
	count, err := scannerrules.Download(cmd.Context(), opts.output, opts.force)
	if err != nil {
		return err
	}
	log.Info().Str("source", scannerrules.ExternalRulesURL).Str("output", opts.output).Int("count", count).Msg("Downloaded optional rules")
	return nil
}
