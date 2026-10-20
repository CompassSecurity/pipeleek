package main

import (
	"github.com/CompassSecurity/pipeleek/internal/cmd"
	"github.com/CompassSecurity/pipeleek/pkg/logging"
)

func main() {
	logging.InstallExitHandler()
	defer logging.StopShortcutListeners()

	err := cmd.Execute()
	if err != nil {
		logging.Exit(1)
	}
}
