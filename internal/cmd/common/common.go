// Package common provides shared functionality for pipeleek platform-specific binaries.
package common

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/format"
	"github.com/CompassSecurity/pipeleek/pkg/httpclient"
	"github.com/CompassSecurity/pipeleek/pkg/logging"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// Version information - set via ldflags during build
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// Log configuration
var (
	originalTermState *term.State
	JsonLogoutput     bool
	LogFile           string
	LogColor          bool
	LogDebug          bool
	LogLevel          string
	IgnoreProxy       bool
	// logFileCloser holds the currently open log file so it can be closed on cleanup.
	logFileCloser io.Closer
)

// TerminalRestorer is a function that can be called to restore terminal state
var TerminalRestorer func()

// CustomWriter wraps an os.File with proper cross-platform newline handling
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

// TerminalRestoringWriter wraps an io.Writer to restore terminal state on fatal logs
type TerminalRestoringWriter struct {
	underlying io.Writer
}

func (w *TerminalRestoringWriter) Write(p []byte) (n int, err error) {
	var logEntry map[string]interface{}
	if err := json.Unmarshal(p, &logEntry); err == nil {
		if level, ok := logEntry["level"].(string); ok && level == "fatal" {
			_, _ = w.underlying.Write(p)
			RestoreTerminalState()
			os.Exit(1)
		}
	}
	return w.underlying.Write(p)
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

// SaveTerminalState saves the current terminal state for later restoration
func SaveTerminalState() {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		state, err := term.GetState(int(os.Stdin.Fd()))
		if err == nil {
			originalTermState = state
		}
	}
}

// RestoreTerminalState restores the terminal to its saved state
func RestoreTerminalState() {
	if originalTermState != nil {
		_ = term.Restore(int(os.Stdin.Fd()), originalTermState)
	}
}

// InitLogger initializes the zerolog logger with the configured options
func InitLogger(cmd *cobra.Command) {
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
		logFileCloser = runLogFile
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

// SetGlobalLogLevel sets the global log level based on the configured options
func SetGlobalLogLevel(cmd *cobra.Command) {
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

// AddCommonFlags adds the common logging and output flags to a cobra command
func AddCommonFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolVarP(&JsonLogoutput, "json", "", false, "Use JSON as log output format")
	cmd.PersistentFlags().StringVarP(&LogFile, "logfile", "l", "", "Log output to a file")
	cmd.PersistentFlags().BoolVarP(&LogDebug, "verbose", "v", false, "Enable debug logging (shortcut for --log-level=debug)")
	cmd.PersistentFlags().StringVar(&LogLevel, "log-level", "", "Set log level globally (debug, info, warn, error). Example: --log-level=warn")
	cmd.PersistentFlags().BoolVar(&LogColor, "color", true, "Enable colored log output (auto-disabled when using --logfile)")
	cmd.PersistentFlags().BoolVar(&IgnoreProxy, "ignore-proxy", false, "Ignore HTTP_PROXY environment variable")
}

// SetupPersistentPreRun sets up the PersistentPreRun handler for logging initialization
func SetupPersistentPreRun(cmd *cobra.Command) {
	cmd.PersistentPreRun = func(c *cobra.Command, args []string) {
		InitLogger(c)
		SetGlobalLogLevel(c)
		httpclient.SetIgnoreProxy(IgnoreProxy)
		go logging.ShortcutListeners(nil)
	}
}

// Run executes the common startup sequence and runs the provided root command
func Run(rootCmd *cobra.Command) {
	SaveTerminalState()
	defer RestoreTerminalState()

	TerminalRestorer = RestoreTerminalState

	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
