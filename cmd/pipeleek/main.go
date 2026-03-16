package main

import (
	"encoding/json"
	"io"
	"os"

	"github.com/CompassSecurity/pipeleek/internal/cmd"
	"golang.org/x/term"
)

var originalTermState *term.State

type TerminalRestoringWriter struct {
	underlying io.Writer
}

func (w *TerminalRestoringWriter) Write(p []byte) (n int, err error) {
	var logEntry map[string]interface{}
	if err := json.Unmarshal(p, &logEntry); err == nil {
		if level, ok := logEntry["level"].(string); ok && level == "fatal" {
			_, _ = w.underlying.Write(p)
			restoreTerminalState()
			os.Exit(1)
		}
	}
	return w.underlying.Write(p)
}

func main() {
	saveTerminalState()
	defer restoreTerminalState()

	cmd.TerminalRestorer = restoreTerminalState

	err := cmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func saveTerminalState() {
	// #nosec G115 -- os.Stdin file descriptor is provided by the runtime and fits into int on supported platforms
	stdinFD := int(os.Stdin.Fd())
	if term.IsTerminal(stdinFD) {
		state, err := term.GetState(stdinFD)
		if err == nil {
			originalTermState = state
		}
	}
}

func restoreTerminalState() {
	if originalTermState != nil {
		// #nosec G115 -- os.Stdin file descriptor is provided by the runtime and fits into int on supported platforms
		stdinFD := int(os.Stdin.Fd())
		_ = term.Restore(stdinFD, originalTermState)
	}
}

// GetTerminalRestoringWriter wraps the given writer to restore terminal state on fatal logs
func GetTerminalRestoringWriter(w io.Writer) io.Writer {
	return &TerminalRestoringWriter{underlying: w}
}
