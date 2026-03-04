package common

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFatalHook_FatalLevelCallsTerminalRestorer(t *testing.T) {
	orig := TerminalRestorer
	defer func() { TerminalRestorer = orig }()

	called := false
	TerminalRestorer = func() { called = true }

	hook := FatalHook{}
	var buf bytes.Buffer
	logger := zerolog.New(&buf)
	event := logger.Fatal()
	hook.Run(event, zerolog.FatalLevel, "test message")

	assert.True(t, called, "TerminalRestorer should be called on fatal level")
}

func TestFatalHook_NonFatalLevelsDoNotCallTerminalRestorer(t *testing.T) {
	orig := TerminalRestorer
	defer func() { TerminalRestorer = orig }()

	levels := []zerolog.Level{
		zerolog.TraceLevel,
		zerolog.DebugLevel,
		zerolog.InfoLevel,
		zerolog.WarnLevel,
		zerolog.ErrorLevel,
	}

	hook := FatalHook{}
	var buf bytes.Buffer
	logger := zerolog.New(&buf)

	for _, lvl := range levels {
		called := false
		TerminalRestorer = func() { called = true }

		event := logger.WithLevel(lvl)
		hook.Run(event, lvl, "test")
		assert.False(t, called, "TerminalRestorer should not be called for level %v", lvl)
	}
}

func TestFatalHook_NilTerminalRestorerDoesNotPanic(t *testing.T) {
	orig := TerminalRestorer
	defer func() { TerminalRestorer = orig }()

	TerminalRestorer = nil
	hook := FatalHook{}

	assert.NotPanics(t, func() {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)
		event := logger.Fatal()
		hook.Run(event, zerolog.FatalLevel, "test")
	})
}

func TestCustomWriter_WritesCorrectly(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY, 0644)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	writer := &CustomWriter{Writer: f}
	testData := []byte(`{"level":"info","message":"hello"}` + "\n")

	n, err := writer.Write(testData)
	assert.NoError(t, err)
	assert.Equal(t, len(testData), n, "Write should return original length")

	require.NoError(t, f.Sync())
	content, err := os.ReadFile(logFile)
	require.NoError(t, err)
	assert.Contains(t, string(content), "hello", "Written content should be readable")
}

func TestCustomWriter_HandlesDataWithoutTrailingNewline(t *testing.T) {
	tmpDir := t.TempDir()
	f, err := os.OpenFile(filepath.Join(tmpDir, "noeol.log"), os.O_CREATE|os.O_WRONLY, 0644)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	writer := &CustomWriter{Writer: f}
	data := []byte(`no trailing newline`)
	n, err := writer.Write(data)
	assert.NoError(t, err)
	assert.Equal(t, len(data), n)
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
			name:          "log-level trace",
			logDebug:      false,
			logLevel:      "trace",
			expectedLevel: zerolog.TraceLevel,
		},
		{
			name:          "log-level debug",
			logDebug:      false,
			logLevel:      "debug",
			expectedLevel: zerolog.DebugLevel,
		},
		{
			name:          "log-level info",
			logDebug:      false,
			logLevel:      "info",
			expectedLevel: zerolog.InfoLevel,
		},
		{
			name:          "log-level warn",
			logDebug:      false,
			logLevel:      "warn",
			expectedLevel: zerolog.WarnLevel,
		},
		{
			name:          "log-level error",
			logDebug:      false,
			logLevel:      "error",
			expectedLevel: zerolog.ErrorLevel,
		},
		{
			name:          "default (no flags) is info",
			logDebug:      false,
			logLevel:      "",
			expectedLevel: zerolog.InfoLevel,
		},
		{
			name:          "invalid log-level defaults to info",
			logDebug:      false,
			logLevel:      "garbage",
			expectedLevel: zerolog.InfoLevel,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origLevel := zerolog.GlobalLevel()
			origLogger := log.Logger
			origDebug := LogDebug
			origLogLevel := LogLevel
			defer func() {
				zerolog.SetGlobalLevel(origLevel)
				log.Logger = origLogger
				LogDebug = origDebug
				LogLevel = origLogLevel
			}()

			// Redirect logger to discard to avoid test output pollution
			log.Logger = zerolog.New(zerolog.MultiLevelWriter()).Level(zerolog.TraceLevel)

			LogDebug = tt.logDebug
			LogLevel = tt.logLevel
			SetGlobalLogLevel(nil)

			assert.Equal(t, tt.expectedLevel, zerolog.GlobalLevel(),
				"global log level should be %v when logDebug=%v, logLevel=%q",
				tt.expectedLevel, tt.logDebug, tt.logLevel)
		})
	}
}

func TestAddCommonFlags(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	AddCommonFlags(cmd)

	flags := cmd.PersistentFlags()

	t.Run("json flag", func(t *testing.T) {
		f := flags.Lookup("json")
		assert.NotNil(t, f, "json flag should be registered")
		assert.Equal(t, "false", f.DefValue, "json flag default should be false")
	})

	t.Run("logfile flag", func(t *testing.T) {
		f := flags.Lookup("logfile")
		assert.NotNil(t, f, "logfile flag should be registered")
		assert.Equal(t, "", f.DefValue, "logfile flag default should be empty")
	})

	t.Run("verbose flag", func(t *testing.T) {
		f := flags.Lookup("verbose")
		assert.NotNil(t, f, "verbose flag should be registered")
		assert.Equal(t, "false", f.DefValue, "verbose flag default should be false")
		assert.Equal(t, "v", f.Shorthand, "verbose flag shorthand should be 'v'")
	})

	t.Run("log-level flag", func(t *testing.T) {
		f := flags.Lookup("log-level")
		assert.NotNil(t, f, "log-level flag should be registered")
		assert.Equal(t, "", f.DefValue, "log-level flag default should be empty string")
	})

	t.Run("color flag", func(t *testing.T) {
		f := flags.Lookup("color")
		assert.NotNil(t, f, "color flag should be registered")
		assert.Equal(t, "true", f.DefValue, "color flag default should be true")
	})

	t.Run("ignore-proxy flag", func(t *testing.T) {
		f := flags.Lookup("ignore-proxy")
		assert.NotNil(t, f, "ignore-proxy flag should be registered")
		assert.Equal(t, "false", f.DefValue, "ignore-proxy flag default should be false")
	})
}

func TestFormatLevelWithHitColor(t *testing.T) {
	tests := []struct {
		name         string
		colorEnabled bool
		level        string
		expectColor  bool
		expectLevel  string
	}{
		{
			name:         "hit level with color",
			colorEnabled: true,
			level:        "hit",
			expectColor:  true,
			expectLevel:  "hit",
		},
		{
			name:         "hit level without color",
			colorEnabled: false,
			level:        "hit",
			expectColor:  false,
			expectLevel:  "hit",
		},
		{
			name:         "info level with color",
			colorEnabled: true,
			level:        "info",
			expectColor:  true,
			expectLevel:  "info",
		},
		{
			name:         "info level without color",
			colorEnabled: false,
			level:        "info",
			expectColor:  false,
			expectLevel:  "info",
		},
		{
			name:         "unknown level",
			colorEnabled: true,
			level:        "custom",
			expectColor:  false,
			expectLevel:  "custom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			formatter := formatLevelWithHitColor(tt.colorEnabled)
			result := formatter(tt.level)

			assert.Contains(t, result, tt.expectLevel,
				"result should contain the level string")
			if tt.expectColor {
				assert.Contains(t, result, "\x1b[",
					"result should contain ANSI escape code when color enabled")
			} else {
				assert.NotContains(t, result, "\x1b[",
					"result should not contain ANSI escape code when color disabled")
			}
		})
	}
}

func TestFormatLevelWithHitColor_NonStringInput(t *testing.T) {
	formatter := formatLevelWithHitColor(true)
	result := formatter(42)
	assert.Equal(t, "", result, "non-string input should return empty string")
}

func TestSetupPersistentPreRun(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	assert.Nil(t, cmd.PersistentPreRun, "PersistentPreRun should be nil before setup")

	SetupPersistentPreRun(cmd)
	assert.NotNil(t, cmd.PersistentPreRun, "PersistentPreRun should be set after setup")
}

// TestInitLogger_ConsoleMode verifies InitLogger sets up a console zerolog writer.
func TestInitLogger_ConsoleMode(t *testing.T) {
	origLogFile := LogFile
	origJson := JsonLogoutput
	origColor := LogColor
	origLogger := log.Logger
	origLogFileCloser := logFileCloser
	defer func() {
		log.Logger = origLogger
		if logFileCloser != nil && logFileCloser != origLogFileCloser {
			_ = logFileCloser.Close()
		}
		logFileCloser = origLogFileCloser
		LogFile = origLogFile
		JsonLogoutput = origJson
		LogColor = origColor
	}()

	tmpDir := t.TempDir()
	LogFile = filepath.Join(tmpDir, "console.log")
	JsonLogoutput = false
	LogColor = false

	cmd := &cobra.Command{Use: "test"}
	InitLogger(cmd)

	log.Info().Msg("console-mode-test-msg")

	content, err := os.ReadFile(LogFile)
	require.NoError(t, err)
	assert.Contains(t, string(content), "console-mode-test-msg")
}

// TestInitLogger_JSONMode verifies InitLogger outputs JSON when JsonLogoutput=true.
func TestInitLogger_JSONMode(t *testing.T) {
	origLogFile := LogFile
	origJson := JsonLogoutput
	origLogger := log.Logger
	origLogFileCloser := logFileCloser
	defer func() {
		log.Logger = origLogger
		if logFileCloser != nil && logFileCloser != origLogFileCloser {
			_ = logFileCloser.Close()
		}
		logFileCloser = origLogFileCloser
		LogFile = origLogFile
		JsonLogoutput = origJson
	}()

	tmpDir := t.TempDir()
	LogFile = filepath.Join(tmpDir, "json.log")
	JsonLogoutput = true

	cmd := &cobra.Command{Use: "test"}
	InitLogger(cmd)

	log.Info().Msg("json-mode-test-msg")

	content, err := os.ReadFile(LogFile)
	require.NoError(t, err)
	s := string(content)
	assert.Contains(t, s, "json-mode-test-msg")
	assert.Contains(t, s, `"level"`, "JSON output should contain level field")
}

// TestInitLogger_NoLogFile verifies InitLogger does not panic when LogFile is empty.
func TestInitLogger_NoLogFile(t *testing.T) {
	origLogFile := LogFile
	origJson := JsonLogoutput
	origLogger := log.Logger
	defer func() {
		LogFile = origLogFile
		JsonLogoutput = origJson
		log.Logger = origLogger
	}()

	LogFile = ""
	JsonLogoutput = false

	cmd := &cobra.Command{Use: "test"}
	assert.NotPanics(t, func() {
		InitLogger(cmd)
	})
}

// TestSaveAndRestoreTerminalState verifies that SaveTerminalState and RestoreTerminalState
// do not panic regardless of whether stdin is a terminal.
func TestSaveAndRestoreTerminalState(t *testing.T) {
	origState := originalTermState
	defer func() { originalTermState = origState }()

	assert.NotPanics(t, func() {
		SaveTerminalState()
	})

	assert.NotPanics(t, func() {
		RestoreTerminalState()
	})
}

// TestRestoreTerminalState_NilState verifies no panic when terminal state was never saved.
func TestRestoreTerminalState_NilState(t *testing.T) {
	origState := originalTermState
	defer func() { originalTermState = origState }()

	originalTermState = nil
	assert.NotPanics(t, func() {
		RestoreTerminalState()
	})
}
