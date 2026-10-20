package system

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/CompassSecurity/pipeleek/pkg/logging"
	"github.com/rs/zerolog/log"
)

type ShutdownHandler func()

func RegisterGracefulShutdownHandler(handler ShutdownHandler) {
	sigChannel := make(chan os.Signal, 1)
	signal.Notify(sigChannel, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChannel
		log.Info().Msg("Received interrupt signal, shutting down gracefully...")
		handler()
		logging.Exit(0)
	}()
}
