package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGlobalVerboseFlagRegistered(t *testing.T) {
	flag := rootCmd.PersistentFlags().Lookup("verbose")
	assert.NotNil(t, flag, "Global verbose flag should be registered")
	assert.Equal(t, "false", flag.DefValue, "verbose flag default should be false")
}

func TestGlobalLogLevelFlagRegistered(t *testing.T) {
	flag := rootCmd.PersistentFlags().Lookup("log-level")
	assert.NotNil(t, flag, "Global log-level flag should be registered")
	assert.Equal(t, "", flag.DefValue, "log-level flag default should be empty string")
}

func TestSetGlobalLogLevel(t *testing.T) {
	tests := []struct {
		name          string
		logDebug      bool
		logLevel      string
		expectedLevel zerolog.Level
	}{
		{
			name:          "verbose flag sets debug level",
			logDebug:      true,
			logLevel:      "",
			expectedLevel: zerolog.DebugLevel,
		},
		{
			name:          "log-level debug sets debug level",
			logDebug:      false,
			logLevel:      "debug",
			expectedLevel: zerolog.DebugLevel,
		},
		{
			name:          "log-level info sets info level",
			logDebug:      false,
			logLevel:      "info",
			expectedLevel: zerolog.InfoLevel,
		},
		{
			name:          "log-level warn sets warn level",
			logDebug:      false,
			logLevel:      "warn",
			expectedLevel: zerolog.WarnLevel,
		},
		{
			name:          "log-level error sets error level",
			logDebug:      false,
			logLevel:      "error",
			expectedLevel: zerolog.ErrorLevel,
		},
		{
			name:          "default (no flags) sets info level",
			logDebug:      false,
			logLevel:      "",
			expectedLevel: zerolog.InfoLevel,
		},
		{
			name:          "invalid log-level defaults to info",
			logDebug:      false,
			logLevel:      "invalid",
			expectedLevel: zerolog.InfoLevel,
		},
		{
			name:          "log-level takes precedence over verbose flag when both set",
			logDebug:      true,
			logLevel:      "info",
			expectedLevel: zerolog.InfoLevel,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore all global state via defer to prevent test contamination
			origLevel := zerolog.GlobalLevel()
			origDebug := LogDebug
			origLogLevel := LogLevel
			defer func() {
				zerolog.SetGlobalLevel(origLevel)
				LogDebug = origDebug
				LogLevel = origLogLevel
			}()

			LogDebug = tt.logDebug
			LogLevel = tt.logLevel
			setGlobalLogLevel(nil)

			assert.Equal(t, tt.expectedLevel, zerolog.GlobalLevel(),
				"log level should be %v for logDebug=%v, logLevel=%q",
				tt.expectedLevel, tt.logDebug, tt.logLevel)
		})
	}
}

func TestGlobalColorFlagRegistered(t *testing.T) {
	flag := rootCmd.PersistentFlags().Lookup("color")
	assert.NotNil(t, flag, "Global color flag should be registered")
	assert.Equal(t, "true", flag.DefValue, "color flag default should be true")
}

func TestGlobalConfigFlagRegistered(t *testing.T) {
	flag := rootCmd.PersistentFlags().Lookup("config")
	assert.NotNil(t, flag, "Global config flag should be registered")
	assert.Equal(t, "", flag.DefValue, "config flag default should be empty string")
}

func TestGlobalLogFileFlagRegistered(t *testing.T) {
	flag := rootCmd.PersistentFlags().Lookup("logfile")
	assert.NotNil(t, flag, "Global logfile flag should be registered")
	assert.Equal(t, "", flag.DefValue, "logfile flag default should be empty string")
}

func TestGlobalIgnoreProxyFlagRegistered(t *testing.T) {
	flag := rootCmd.PersistentFlags().Lookup("ignore-proxy")
	assert.NotNil(t, flag, "Global ignore-proxy flag should be registered")
	assert.Equal(t, "false", flag.DefValue, "ignore-proxy flag default should be false")
}

func TestGlobalJSONFlagRegistered(t *testing.T) {
	flag := rootCmd.PersistentFlags().Lookup("json")
	assert.NotNil(t, flag, "Global json flag should be registered")
	assert.Equal(t, "false", flag.DefValue, "json flag default should be false")
}

func TestPersistentPreRunRegistered(t *testing.T) {
	assert.NotNil(t, rootCmd.PersistentPreRun, "PersistentPreRun should be registered")
}

func TestTerminalRestorer(t *testing.T) {
	t.Run("TerminalRestorer_can_be_set", func(t *testing.T) {
		originalRestorer := TerminalRestorer
		defer func() { TerminalRestorer = originalRestorer }()

		called := false
		TerminalRestorer = func() { called = true }

		TerminalRestorer()
		assert.True(t, called, "TerminalRestorer should be callable")
	})

	t.Run("TerminalRestorer_nil_safe", func(t *testing.T) {
		originalRestorer := TerminalRestorer
		defer func() { TerminalRestorer = originalRestorer }()

		TerminalRestorer = nil
		assert.NotPanics(t, func() {
			if TerminalRestorer != nil {
				TerminalRestorer()
			}
		})
	})
}

func TestFatalHook(t *testing.T) {
	t.Run("fatal_level_calls_TerminalRestorer", func(t *testing.T) {
		originalRestorer := TerminalRestorer
		defer func() { TerminalRestorer = originalRestorer }()

		called := false
		TerminalRestorer = func() { called = true }

		hook := FatalHook{}

		var buf bytes.Buffer
		logger := zerolog.New(&buf)
		event := logger.Fatal()

		hook.Run(event, zerolog.FatalLevel, "test")

		assert.True(t, called, "TerminalRestorer should be called for fatal level")
	})

	t.Run("non_fatal_level_does_not_call_TerminalRestorer", func(t *testing.T) {
		originalRestorer := TerminalRestorer
		defer func() { TerminalRestorer = originalRestorer }()

		called := false
		TerminalRestorer = func() { called = true }

		hook := FatalHook{}

		levels := []zerolog.Level{
			zerolog.TraceLevel,
			zerolog.DebugLevel,
			zerolog.InfoLevel,
			zerolog.WarnLevel,
			zerolog.ErrorLevel,
		}

		var buf bytes.Buffer
		logger := zerolog.New(&buf)
		for _, lvl := range levels {
			event := logger.WithLevel(lvl)
			hook.Run(event, lvl, "test")
			assert.False(t, called, "TerminalRestorer should not be called for non-fatal levels")
		}
	})

	t.Run("nil_TerminalRestorer_does_not_panic", func(t *testing.T) {
		originalRestorer := TerminalRestorer
		defer func() { TerminalRestorer = originalRestorer }()

		TerminalRestorer = nil
		hook := FatalHook{}

		assert.NotPanics(t, func() {
			var buf bytes.Buffer
			logger := zerolog.New(&buf)
			event := logger.Fatal()
			hook.Run(event, zerolog.FatalLevel, "test")
		})
	})
}

func TestCustomWriter_WritesCorrectly(t *testing.T) {
	t.Run("Writes_log_to_file", func(t *testing.T) {
		tmpDir := t.TempDir()
		logFile := filepath.Join(tmpDir, "test.log")

		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY, 0644)
		require.NoError(t, err)
		defer func() { _ = f.Close() }()

		writer := &CustomWriter{Writer: f}

		testLog := []byte(`{"level":"info","message":"test"}` + "\n")
		n, err := writer.Write(testLog)

		assert.NoError(t, err)
		assert.Equal(t, len(testLog), n, "Should return original length")

		_ = f.Close()
		content, err := os.ReadFile(logFile)
		require.NoError(t, err)
		assert.Contains(t, string(content), "test", "Log content should be written")
	})
}

func TestInitLogger_DefaultConsole_NotJSON(t *testing.T) {
	// Save globals
	origLogFile := LogFile
	origJson := JsonLogoutput
	origColor := LogColor
	defer func() {
		LogFile = origLogFile
		JsonLogoutput = origJson
		LogColor = origColor
	}()

	// Use a temp file as output target
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "console.log")
	LogFile = logFile
	JsonLogoutput = false
	LogColor = false

	initLogger(rootCmd)
	t.Cleanup(func() { CloseLogger() })

	log.Info().Msg("hello-console")

	content, err := os.ReadFile(logFile)
	require.NoError(t, err)
	s := string(content)
	assert.Contains(t, s, "hello-console", "message should be present")
	assert.NotContains(t, s, "\"level\":\"info\"", "console output should not be JSON")
}

func TestInitLogger_JSON_WhenFlagSet(t *testing.T) {
	// Save globals
	origLogFile := LogFile
	origJson := JsonLogoutput
	defer func() {
		LogFile = origLogFile
		JsonLogoutput = origJson
	}()

	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "json.log")
	LogFile = logFile
	JsonLogoutput = true

	initLogger(rootCmd)
	t.Cleanup(func() { CloseLogger() })

	log.Info().Msg("hello-json")

	content, err := os.ReadFile(logFile)
	require.NoError(t, err)
	s := string(content)
	assert.Contains(t, s, "hello-json", "message should be present")
	assert.Contains(t, s, "\"level\":\"info\"", "JSON output should contain level field")
}

func TestVersionFlagRegistered(t *testing.T) {
	// Version flag is automatically added by Cobra when Version is set on the command
	// Check that the rootCmd has a version set
	assert.NotEmpty(t, rootCmd.Version, "rootCmd should have a version set")
}

func TestGetVersion(t *testing.T) {
	// Save original values
	originalVersion := Version
	originalCommit := Commit
	originalDate := Date
	defer func() {
		Version = originalVersion
		Commit = originalCommit
		Date = originalDate
	}()

	t.Run("returns default dev version", func(t *testing.T) {
		Version = "dev"
		Commit = "none"
		Date = "unknown"
		result := getVersion()
		assert.Equal(t, "dev", result)
	})

	t.Run("returns git tag version", func(t *testing.T) {
		Version = "v1.2.3"
		Commit = "abc123"
		Date = "2025-11-17"
		result := getVersion()
		assert.Equal(t, "v1.2.3", result)
	})

	t.Run("returns commit hash when not on tag", func(t *testing.T) {
		Version = "70926c9"
		Commit = "70926c9"
		Date = "2025-11-17"
		result := getVersion()
		assert.Equal(t, "70926c9", result)
	})
}

func TestRootCmdHasVersion(t *testing.T) {
	assert.NotEmpty(t, rootCmd.Version, "rootCmd should have a version")
}

// TestFormatLevelWithHitColor_ColorEnabled verifies each log level gets the correct
// color escape code when color output is enabled.
func TestFormatLevelWithHitColor_ColorEnabled(t *testing.T) {
	formatter := formatLevelWithHitColor(true)

	tests := []struct {
		level    string
		wantCode string
	}{
		{"hit", "\x1b[35m"},   // magenta
		{"trace", "\x1b[90m"}, // dark grey
		{"info", "\x1b[32m"},  // green
		{"warn", "\x1b[33m"},  // yellow
		{"error", "\x1b[31m"}, // red
		{"fatal", "\x1b[31m"}, // red
		{"panic", "\x1b[31m"}, // red
		{"debug", "debug"},    // no color for debug - returned as-is
	}

	for _, tt := range tests {
		t.Run("level_"+tt.level, func(t *testing.T) {
			result := formatter(tt.level)
			assert.Contains(t, result, tt.wantCode, "level=%q should contain color code %q", tt.level, tt.wantCode)
		})
	}
}

// TestFormatLevelWithHitColor_ColorDisabled verifies that every level is returned
// unchanged (no escape codes) when color output is disabled.
func TestFormatLevelWithHitColor_ColorDisabled(t *testing.T) {
	formatter := formatLevelWithHitColor(false)

	levels := []string{"hit", "trace", "debug", "info", "warn", "error", "fatal", "panic", "unknown"}
	for _, level := range levels {
		t.Run("level_"+level, func(t *testing.T) {
			result := formatter(level)
			assert.Equal(t, level, result, "color disabled: level=%q should be returned unchanged", level)
		})
	}
}

// TestFormatLevelWithHitColor_UnknownLevel verifies that unknown levels are passed through.
func TestFormatLevelWithHitColor_UnknownLevel(t *testing.T) {
	formatter := formatLevelWithHitColor(true)
	result := formatter("custom-level")
	// Unknown levels fall through to the default case which returns the level unchanged
	assert.Equal(t, "custom-level", result)
}

// TestFormatLevelWithHitColor_NonStringInput verifies that non-string input returns "".
func TestFormatLevelWithHitColor_NonStringInput(t *testing.T) {
	formatter := formatLevelWithHitColor(true)
	result := formatter(42)
	assert.Equal(t, "", result)
}

// TestLoadConfigFile_NoConfigFile verifies that loadConfigFile does not panic or error
// when no config file path is set (default empty string).
func TestLoadConfigFile_NoConfigFile(t *testing.T) {
	origConfigFile := ConfigFile
	defer func() { ConfigFile = origConfigFile }()

	ConfigFile = ""
	assert.NotPanics(t, func() {
		loadConfigFile(rootCmd)
	})
}
