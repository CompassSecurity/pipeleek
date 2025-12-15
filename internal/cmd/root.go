package cmd

import (
	"bytes"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/CompassSecurity/pipeleek/internal/cmd/bitbucket"
	"github.com/CompassSecurity/pipeleek/internal/cmd/devops"
	"github.com/CompassSecurity/pipeleek/internal/cmd/docs"
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitea"
	"github.com/CompassSecurity/pipeleek/internal/cmd/github"
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab"
	"github.com/CompassSecurity/pipeleek/pkg/config"
	"github.com/CompassSecurity/pipeleek/pkg/format"
	"github.com/CompassSecurity/pipeleek/pkg/httpclient"
	"github.com/CompassSecurity/pipeleek/pkg/logging"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// TerminalRestorer is a function that can be called to restore terminal state
var TerminalRestorer func()

// Version information - set via ldflags during build
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

var (
	rootCmd = &cobra.Command{
		Use:     "pipeleek",
		Short:   "Scan job logs and artifacts for secrets",
		Long:    "Pipeleek is a tool designed to scan CI/CD job output logs and artifacts for potential secrets.",
		Example: "pipeleek gl scan --token glpat-xxxxxxxxxxx --gitlab https://gitlab.com",
		Version: getVersion(),
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			loadConfigFile(cmd)
			initLogger(cmd)
			setGlobalLogLevel(cmd)
			httpclient.SetIgnoreProxy(IgnoreProxy)
			go logging.ShortcutListeners(nil)
		},
	}
	JsonLogoutput bool
	LogFile       string
	LogColor      bool
	LogDebug      bool
	LogLevel      string
	IgnoreProxy   bool
	ConfigFile    string
)

func Execute() error {
	return rootCmd.Execute()
}

// getVersion returns the version string in the format: version (commit) built on date
func getVersion() string {
	return Version
}

func init() {
	rootCmd.AddCommand(github.NewGitHubRootCmd())
	rootCmd.AddCommand(gitlab.NewGitLabRootCmd())
	rootCmd.AddCommand(gitlab.NewGitLabRootUnauthenticatedCmd())
	rootCmd.AddCommand(bitbucket.NewBitBucketRootCmd())
	rootCmd.AddCommand(devops.NewAzureDevOpsRootCmd())
	rootCmd.AddCommand(gitea.NewGiteaRootCmd())
	rootCmd.AddCommand(docs.NewDocsCmd(rootCmd))
	rootCmd.PersistentFlags().StringVar(&ConfigFile, "config", "", "Config file path (YAML, JSON, or TOML). Example: ~/.config/pipeleek/config.yaml")
	rootCmd.PersistentFlags().BoolVarP(&JsonLogoutput, "json", "", false, "Use JSON as log output format")
	rootCmd.PersistentFlags().StringVarP(&LogFile, "logfile", "l", "", "Log output to a file")
	rootCmd.PersistentFlags().BoolVarP(&LogDebug, "verbose", "v", false, "Enable debug logging (shortcut for --log-level=debug)")
	rootCmd.PersistentFlags().StringVar(&LogLevel, "log-level", "", "Set log level globally (debug, info, warn, error). Example: --log-level=warn")
	rootCmd.PersistentFlags().BoolVar(&LogColor, "color", true, "Enable colored log output (auto-disabled when using --logfile)")
	rootCmd.PersistentFlags().BoolVar(&IgnoreProxy, "ignore-proxy", false, "Ignore HTTP_PROXY environment variable")

	// Set custom version template to show detailed version info
	rootCmd.SetVersionTemplate(`{{.Version}}
`)

	rootCmd.AddGroup(&cobra.Group{ID: "GitHub", Title: "GitHub Commands"})
	rootCmd.AddGroup(&cobra.Group{ID: "GitLab", Title: "GitLab Commands"})
	rootCmd.AddGroup(&cobra.Group{ID: "Helper", Title: "Various Helper Commands"})
	rootCmd.AddGroup(&cobra.Group{ID: "BitBucket", Title: "BitBucket Commands"})
	rootCmd.AddGroup(&cobra.Group{ID: "AzureDevOps", Title: "Azure DevOps Commands"})
	rootCmd.AddGroup(&cobra.Group{ID: "Gitea", Title: "Gitea Commands"})
}

type CustomWriter struct {
	Writer *os.File
}

func (cw *CustomWriter) Write(p []byte) (n int, err error) {
	originalLen := len(p)

	if bytes.HasSuffix(p, []byte("\n")) {
		p = bytes.TrimSuffix(p, []byte("\n"))
	}

	// necessary as to: https://github.com/rs/zerolog/blob/master/log.go#L474
	newlineChars := []byte("\n")
	if runtime.GOOS == "windows" {
		newlineChars = []byte("\n\r")
	}

	modified := append(p, newlineChars...)

	written, err := cw.Writer.Write(modified)
	if err != nil {
		return 0, err
	}

	if written != len(modified) {
		return 0, io.ErrShortWrite
	}

	return originalLen, nil
}

// FatalHook is a zerolog hook that restores terminal state before fatal exits
type FatalHook struct{}

func (h FatalHook) Run(e *zerolog.Event, level zerolog.Level, msg string) {
	if level == zerolog.FatalLevel {
		if TerminalRestorer != nil {
			TerminalRestorer()
		}
	}
}

func initLogger(cmd *cobra.Command) {
	defaultOut := &CustomWriter{Writer: os.Stdout}
	colorEnabled := LogColor

	if LogFile != "" {
		// #nosec G304 - User-provided log file path via --log-file flag, user controls their own filesystem
		runLogFile, err := os.OpenFile(
			LogFile,
			os.O_APPEND|os.O_CREATE|os.O_WRONLY,
			format.FileUserReadWrite,
		)
		if err != nil {
			panic(err)
		}
		defaultOut = &CustomWriter{Writer: runLogFile}

		rootFlags := cmd.Root().PersistentFlags()
		if !rootFlags.Changed("color") {
			colorEnabled = false
		}
	}

	fatalHook := FatalHook{}

	if JsonLogoutput {
		// For JSON output, wrap with HitLevelWriter to transform level field
		hitWriter := &logging.HitLevelWriter{}
		hitWriter.SetOutput(defaultOut)
		logging.SetGlobalHitWriter(hitWriter)
		log.Logger = zerolog.New(hitWriter).With().Timestamp().Logger().Hook(fatalHook)
	} else {
		// For console output, use custom FormatLevel to color the hit level
		output := zerolog.ConsoleWriter{
			Out:         defaultOut,
			TimeFormat:  time.RFC3339,
			NoColor:     !colorEnabled,
			FormatLevel: formatLevelWithHitColor(colorEnabled),
		}
		// Wrap with HitLevelWriter to transform JSON before ConsoleWriter processes it
		hitWriter := &logging.HitLevelWriter{}
		hitWriter.SetOutput(&output)
		logging.SetGlobalHitWriter(hitWriter)
		log.Logger = zerolog.New(hitWriter).With().Timestamp().Logger().Hook(fatalHook)
	}
}

// formatLevelWithHitColor returns a custom level formatter that adds a distinct color for the "hit" level.
// The hit level uses magenta (color 35) to distinguish it from other log levels.
func formatLevelWithHitColor(colorEnabled bool) zerolog.Formatter {
	return func(i interface{}) string {
		var level string
		if ll, ok := i.(string); ok {
			level = ll
		} else {
			return ""
		}

		if !colorEnabled {
			return level
		}

		// Custom color for hit level - using bright magenta (35) to stand out
		if level == "hit" {
			return "\x1b[35m" + level + "\x1b[0m"
		}

		// Use zerolog's default colors for other levels
		switch level {
		case "trace":
			return "\x1b[90m" + level + "\x1b[0m"
		case "debug":
			return level
		case "info":
			return "\x1b[32m" + level + "\x1b[0m"
		case "warn":
			return "\x1b[33m" + level + "\x1b[0m"
		case "error":
			return "\x1b[31m" + level + "\x1b[0m"
		case "fatal":
			return "\x1b[31m" + level + "\x1b[0m"
		case "panic":
			return "\x1b[31m" + level + "\x1b[0m"
		default:
			return level
		}
	}
}

func setGlobalLogLevel(cmd *cobra.Command) {
	if LogLevel != "" {
		switch LogLevel {
		case "trace":
			zerolog.SetGlobalLevel(zerolog.TraceLevel)
			log.Trace().Msg("Log level set to trace (explicit)")
		case "debug":
			zerolog.SetGlobalLevel(zerolog.DebugLevel)
			log.Debug().Msg("Log level set to debug (explicit)")
		case "info":
			zerolog.SetGlobalLevel(zerolog.InfoLevel)
			log.Info().Msg("Log level set to info (explicit)")
		case "warn":
			zerolog.SetGlobalLevel(zerolog.WarnLevel)
			log.Warn().Msg("Log level set to warn (explicit)")
		case "error":
			zerolog.SetGlobalLevel(zerolog.ErrorLevel)
			log.Error().Msg("Log level set to error (explicit)")
		default:
			zerolog.SetGlobalLevel(zerolog.InfoLevel)
			log.Warn().Str("logLevelSpecified", LogLevel).Msg("Invalid log level, defaulting to info")
		}
		return
	}

	if LogDebug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Debug().Msg("Log level set to debug (-v)")
		return
	}

	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log.Info().Msg("Log level set to info (default)")
}

// loadConfigFile loads the configuration from a file if specified
func loadConfigFile(cmd *cobra.Command) {
	// Load config file if specified or search in standard locations
	_, err := config.LoadConfig(ConfigFile)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load configuration file")
	}
}
