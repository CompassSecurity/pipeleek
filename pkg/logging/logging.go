package logging

import (
	"sync"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func SetLogLevel(verbose bool) {
	if verbose {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Debug().Msg("Verbose log output enabled")
	}
}

type ShortcutStatusFN func() *zerolog.Event

var (
	statusHookMutex sync.RWMutex
	statusHook      ShortcutStatusFN
)

func RegisterStatusHook(hook ShortcutStatusFN) {
	statusHookMutex.Lock()
	defer statusHookMutex.Unlock()
	statusHook = hook
}

func GetStatusHook() ShortcutStatusFN {
	statusHookMutex.RLock()
	defer statusHookMutex.RUnlock()
	if statusHook != nil {
		return statusHook
	}
	return defaultStatusHook
}

func defaultStatusHook() *zerolog.Event {
	return log.Info().Str("status", "🤖 still at it - doing my leeky thing.")
}

func ShortcutListeners(status ShortcutStatusFN) {
	if err := shortcuts.start(); err != nil {
		log.Error().Err(err).Msg("Failed hooking keyboard bindings")
	}
}

func handleShortcut(key string) bool {
	switch key {
	case "\x03", "\x1b":
		return true
	case "t", "d", "i", "w", "e":
		level := map[string]zerolog.Level{
			"t": zerolog.TraceLevel,
			"d": zerolog.DebugLevel,
			"i": zerolog.InfoLevel,
			"w": zerolog.WarnLevel,
			"e": zerolog.ErrorLevel,
		}[key]
		zerolog.SetGlobalLevel(level)
		log.Info().Str("logLevel", level.String()).Msg("New Log level")
	case "s":
		GetStatusHook()().Msg("Status")
	}
	return false
}
