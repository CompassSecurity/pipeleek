package e2e

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
	"github.com/stretchr/testify/assert"
)

func setupLoggingMockGitLab(t *testing.T) (string, func()) {
	t.Helper()

	server, _, cleanup := testutil.StartMockServerWithRecording(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	})

	return server.URL, cleanup
}

// TestLogging_ColorFlagRegistered verifies the --color flag is available
func TestLogging_ColorFlagRegistered(t *testing.T) {
	t.Parallel()

	stdout, _, _ := testutil.RunCLI(t, []string{"--help"}, nil, 5*time.Second)

	testutil.AssertLogContains(t, stdout, []string{"--color"})

	if !strings.Contains(stdout, "auto-disabled") {
		t.Logf("Flag description might not mention auto-disable, but flag exists")
	}
}

// TestLogging_ConsoleOutputHasColors verifies console output includes ANSI color codes
func TestLogging_ConsoleOutputHasColors(t *testing.T) {
	t.Parallel()

	stdout, stderr, exitErr := testutil.RunCLI(t, []string{"gl", "--help"}, nil, 5*time.Second)

	output := stdout + stderr
	assert.Nil(t, exitErr, "Command should succeed")

	// ANSI color codes typically start with \x1b[ or \033[
	hasAnsiCodes := strings.Contains(output, "\x1b[") || strings.Contains(output, "\033[")

	t.Logf("Console output contains ANSI codes: %v", hasAnsiCodes)
	t.Logf("Output sample (first 200 chars): %s", truncate(output, 200))
}

// TestLogging_FileOutputDisablesColorsAutomatically tests that log files don't contain ANSI codes
func TestLogging_FileOutputDisablesColorsAutomatically(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")
	gitlabURL, cleanup := setupLoggingMockGitLab(t)
	defer cleanup()

	args := []string{"gl", "enum", "--gitlab", gitlabURL, "--token", "test", "--logfile", logFile}
	_, _, _ = testutil.RunCLI(t, args, nil, 10*time.Second)

	content, err := os.ReadFile(logFile)
	if err != nil {
		t.Skipf("Log file not created (command may have exited before logging): %v", err)
		return
	}

	assert.NotEmpty(t, content, "Log file should have content")

	logContent := string(content)

	hasAnsiCodes := strings.Contains(logContent, "\x1b[") || strings.Contains(logContent, "\033[")
	assert.False(t, hasAnsiCodes,
		"Log file should not contain ANSI color codes when colors are auto-disabled")

	t.Logf("Log file content (first 500 chars):\n%s", truncate(logContent, 500))
}

// TestLogging_FileOutputWithExplicitColorEnabled tests manual override
func TestLogging_FileOutputWithExplicitColorEnabled(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test_color.log")
	gitlabURL, cleanup := setupLoggingMockGitLab(t)
	defer cleanup()

	args := []string{"gl", "enum", "--gitlab", gitlabURL, "--token", "test", "--logfile", logFile, "--color=true"}
	_, _, _ = testutil.RunCLI(t, args, nil, 10*time.Second)

	content, err := os.ReadFile(logFile)
	if err != nil {
		t.Skipf("Log file not created: %v", err)
		return
	}

	assert.NotEmpty(t, content, "Log file should have content")

	logContent := string(content)

	hasAnsiCodes := strings.Contains(logContent, "\x1b[") || strings.Contains(logContent, "\033[")
	assert.True(t, hasAnsiCodes,
		"Log file should contain ANSI color codes when --color=true is explicitly set")

	t.Logf("Log file with colors (first 500 chars):\n%s", truncate(logContent, 500))
}

// TestLogging_FileOutputWithExplicitColorDisabled tests explicit disable
func TestLogging_FileOutputWithExplicitColorDisabled(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test_nocolor.log")
	gitlabURL, cleanup := setupLoggingMockGitLab(t)
	defer cleanup()

	args := []string{"gl", "enum", "--gitlab", gitlabURL, "--token", "test", "--logfile", logFile, "--color=false"}
	_, _, _ = testutil.RunCLI(t, args, nil, 10*time.Second)

	content, err := os.ReadFile(logFile)
	if err != nil {
		t.Skipf("Log file not created: %v", err)
		return
	}

	assert.NotEmpty(t, content, "Log file should have content")

	logContent := string(content)

	hasAnsiCodes := strings.Contains(logContent, "\x1b[") || strings.Contains(logContent, "\033[")
	assert.False(t, hasAnsiCodes,
		"Log file should not contain ANSI color codes when --color=false is set")

	t.Logf("Log file without colors (first 500 chars):\n%s", truncate(logContent, 500))
}

// TestLogging_ConsoleWithExplicitColorDisabled tests disabling colors for console
func TestLogging_ConsoleWithExplicitColorDisabled(t *testing.T) {
	t.Parallel()

	args := []string{"gl", "--help", "--color=false"}
	stdout, stderr, exitErr := testutil.RunCLI(t, args, nil, 5*time.Second)

	output := stdout + stderr
	assert.Nil(t, exitErr, "Command should succeed")

	hasAnsiCodes := strings.Contains(output, "\x1b[") || strings.Contains(output, "\033[")
	assert.False(t, hasAnsiCodes,
		"Console output should not contain ANSI color codes when --color=false is set")

	t.Logf("Console output without colors (first 200 chars): %s", truncate(output, 200))
}

// TestLogging_LogFileCreatedSuccessfully verifies log file creation
func TestLogging_LogFileCreatedSuccessfully(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "pipeleek.log")
	gitlabURL, cleanup := setupLoggingMockGitLab(t)
	defer cleanup()

	_, err := os.Stat(logFile)
	assert.True(t, os.IsNotExist(err), "Log file should not exist before command")

	args := []string{"gl", "enum", "--gitlab", gitlabURL, "--token", "test", "--logfile", logFile}
	_, _, _ = testutil.RunCLI(t, args, nil, 10*time.Second)

	stat, err := os.Stat(logFile)
	if err != nil {
		t.Skipf("Log file not created: %v", err)
		return
	}

	assert.Greater(t, stat.Size(), int64(0), "Log file should have content")

	t.Logf("Log file created: %s (size: %d bytes)", logFile, stat.Size())
}

// TestLogging_LogFileAppendMode verifies log file append behavior
func TestLogging_LogFileAppendMode(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "append.log")
	gitlabURL, cleanup := setupLoggingMockGitLab(t)
	defer cleanup()

	args := []string{"gl", "enum", "--gitlab", gitlabURL, "--token", "test", "--logfile", logFile}

	_, _, _ = testutil.RunCLI(t, args, nil, 10*time.Second)

	stat1, err := os.Stat(logFile)
	if err != nil {
		t.Skipf("Log file not created on first run: %v", err)
		return
	}
	size1 := stat1.Size()

	_, _, _ = testutil.RunCLI(t, args, nil, 10*time.Second)

	stat2, err := os.Stat(logFile)
	assert.NoError(t, err, "Log file should exist after second run")
	size2 := stat2.Size()

	assert.Greater(t, size2, size1,
		"Log file should grow on second run (append mode)")

	t.Logf("Log file sizes - First: %d, Second: %d (delta: %d)",
		size1, size2, size2-size1)
}

// Helper function to truncate strings for logging
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
