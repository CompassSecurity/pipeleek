package main

import (
	"os"

	"github.com/CompassSecurity/pipeleek/internal/cmd"
	"golang.org/x/term"
)

var originalTermState *term.State

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
