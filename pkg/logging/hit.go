package logging

import (
	"encoding/json"
	"io"
	"os"
	"sync"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// SecretType defines the source type of a detected secret.
type SecretType string

const (
	// SecretTypeLog indicates a secret found in CI/CD logs.
	SecretTypeLog SecretType = "log"
	// SecretTypeArchive indicates a secret found in an archive/artifact.
	SecretTypeArchive SecretType = "archive"
	// NestedArchive indicates a secret found in a nested archive.
	SecretTypeNestedArchive SecretType = "nested-archive"
	// SecretTypeDotenv indicates a secret found in a dotenv file.
	SecretTypeDotenv SecretType = "dotenv"
)

// HitLevel defines a custom log level for security finding hits.
// Implemented as WarnLevel but transformed to "hit" in output.
const HitLevel zerolog.Level = zerolog.WarnLevel

// HitLevelWriter wraps an io.Writer to transform logs with "level":"warn" to "level":"hit".
type HitLevelWriter struct {
	out       io.Writer
	mu        sync.Mutex
	nextIsHit bool
}

func (w *HitLevelWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	isHit := w.nextIsHit
	w.nextIsHit = false
	w.mu.Unlock()

	if isHit && len(p) > 0 {
		var logEntry map[string]interface{}
		if err := json.Unmarshal(p, &logEntry); err == nil {
			if logEntry["level"] == "warn" || logEntry["level"] == "error" {
				logEntry["level"] = "hit"
			}
			delete(logEntry, "_hit")

			if newBytes, err := json.Marshal(logEntry); err == nil {
				newBytes = append(newBytes, '\n')
				return w.out.Write(newBytes)
			}
		}
	}

	return w.out.Write(p)
}

func (w *HitLevelWriter) markNextAsHit() {
	w.mu.Lock()
	w.nextIsHit = true
	w.mu.Unlock()
}

func (w *HitLevelWriter) SetOutput(out io.Writer) {
	w.mu.Lock()
	w.out = out
	w.mu.Unlock()
}

// NewHitLevelWriter creates a new HitLevelWriter wrapping the given io.Writer.
func NewHitLevelWriter(out io.Writer) *HitLevelWriter {
	return &HitLevelWriter{out: out}
}

// HitEvent wraps a zerolog.Event for hit-level logging with "level":"hit" output.
type HitEvent struct {
	event  *zerolog.Event
	writer *HitLevelWriter
}

func (h *HitEvent) Str(key, val string) *HitEvent {
	h.event.Str(key, val)
	return h
}

func (h *HitEvent) Int(key string, val int) *HitEvent {
	h.event.Int(key, val)
	return h
}

func (h *HitEvent) Bool(key string, val bool) *HitEvent {
	h.event.Bool(key, val)
	return h
}

func (h *HitEvent) Err(err error) *HitEvent {
	h.event.Err(err)
	return h
}

// Engine adds the detection engine field, only when debug logging is enabled.
func (h *HitEvent) Engine(engine string) *HitEvent {
	if engine != "" && zerolog.GlobalLevel() <= zerolog.DebugLevel {
		h.event.Str("engine", engine)
	}
	return h
}

func (h *HitEvent) Msg(msg string) {
	if h.writer != nil {
		h.writer.markNextAsHit()
	}
	h.event.Bool("_hit", true).Msg(msg)
}

var globalHitWriter *HitLevelWriter
var globalHitWriterOnce sync.Once

func setupGlobalHitWriter() {
	globalHitWriterOnce.Do(func() {
		out := os.Stderr
		globalHitWriter = &HitLevelWriter{out: out}
		log.Logger = zerolog.New(globalHitWriter).With().Timestamp().Logger()
	})
}

// Hit creates a hit-level log event for security findings.
// Always emitted regardless of global log level.
// Example: logging.Hit().Str("rule", "secret-key").Msg("HIT")
func Hit() *HitEvent {
	if globalHitWriter == nil {
		setupGlobalHitWriter()
	}
	return &HitEvent{
		event:  log.WithLevel(zerolog.ErrorLevel),
		writer: globalHitWriter,
	}
}

// ParseLevel extends zerolog's ParseLevel to support "hit" level.
func ParseLevel(levelStr string) (zerolog.Level, error) {
	if levelStr == "hit" {
		return HitLevel, nil
	}
	return zerolog.ParseLevel(levelStr)
}

// SetGlobalHitWriter sets the global HitLevelWriter (for testing only).
func SetGlobalHitWriter(writer *HitLevelWriter) {
	globalHitWriter = writer
}
