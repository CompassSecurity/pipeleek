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
	if flag == nil {
		t.Fatal("Global verbose flag not registered")
	}
}

func TestGlobalLogLevelFlagRegistered(t *testing.T) {
	flag := rootCmd.PersistentFlags().Lookup("log-level")
	if flag == nil {
		t.Fatal("Global log-level flag not registered")
	}
}

func TestSetGlobalLogLevel_VerboseFlag(t *testing.T) {
	LogDebug = true
	LogLevel = ""
	setGlobalLogLevel(nil)
	if zerolog.GlobalLevel() != zerolog.DebugLevel {
		t.Errorf("Expected DebugLevel with -v flag, got %v", zerolog.GlobalLevel())
	}
	LogDebug = false
}

func TestSetGlobalLogLevel_LogLevelDebug(t *testing.T) {
	LogDebug = false
	LogLevel = "debug"
	setGlobalLogLevel(nil)
	if zerolog.GlobalLevel() != zerolog.DebugLevel {
		t.Errorf("Expected DebugLevel, got %v", zerolog.GlobalLevel())
	}
	LogLevel = ""
}

func TestSetGlobalLogLevel_Info(t *testing.T) {
	LogDebug = false
	LogLevel = "info"
	setGlobalLogLevel(nil)
	if zerolog.GlobalLevel() != zerolog.InfoLevel {
		t.Errorf("Expected InfoLevel, got %v", zerolog.GlobalLevel())
	}
	LogLevel = ""
}

func TestSetGlobalLogLevel_Warn(t *testing.T) {
	LogDebug = false
	LogLevel = "warn"
	setGlobalLogLevel(nil)
	if zerolog.GlobalLevel() != zerolog.WarnLevel {
		t.Errorf("Expected WarnLevel, got %v", zerolog.GlobalLevel())
	}
	LogLevel = ""
}

func TestSetGlobalLogLevel_Error(t *testing.T) {
	LogDebug = false
	LogLevel = "error"
	setGlobalLogLevel(nil)
	if zerolog.GlobalLevel() != zerolog.ErrorLevel {
		t.Errorf("Expected ErrorLevel, got %v", zerolog.GlobalLevel())
	}
	LogLevel = ""
}

func TestSetGlobalLogLevel_Default(t *testing.T) {
	LogDebug = false
	LogLevel = ""
	setGlobalLogLevel(nil)
	if zerolog.GlobalLevel() != zerolog.InfoLevel {
		t.Errorf("Expected InfoLevel for default, got %v", zerolog.GlobalLevel())
	}
}

func TestSetGlobalLogLevel_Invalid(t *testing.T) {
	LogDebug = false
	LogLevel = "invalid"
	setGlobalLogLevel(nil)
	if zerolog.GlobalLevel() != zerolog.InfoLevel {
		t.Errorf("Expected InfoLevel for invalid, got %v", zerolog.GlobalLevel())
	}
}

func TestGlobalColorFlagRegistered(t *testing.T) {
	flag := rootCmd.PersistentFlags().Lookup("color")
	if flag == nil {
		t.Fatal("Global color flag not registered")
		return
	}

	if flag.DefValue != "true" {
		t.Errorf("Expected default value 'true' for color flag, got %s", flag.DefValue)
	}
}

func TestGlobalConfigFlagRegistered(t *testing.T) {
	flag := rootCmd.PersistentFlags().Lookup("config")
	if flag == nil {
		t.Fatal("Global config flag not registered")
	}
}

func TestGlobalLogFileFlagRegistered(t *testing.T) {
	flag := rootCmd.PersistentFlags().Lookup("logfile")
	if flag == nil {
		t.Fatal("Global logfile flag not registered")
	}
}

func TestPersistentPreRunRegistered(t *testing.T) {
	if rootCmd.PersistentPreRun == nil {
		t.Fatal("PersistentPreRun should be registered")
	}
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
