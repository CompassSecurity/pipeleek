package logging

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/term"
)

type shortcutTerminal struct {
	mu      sync.Mutex
	session *shortcutSession
}

type shortcutSession struct {
	input   shortcutInput
	restore func() error
}

type shortcutInput interface {
	io.ReadWriteCloser
	Fd() uintptr
	Name() string
}

var shortcuts shortcutTerminal

// InstallExitHandler routes fatal logs through the same cleanup as other exits.
func InstallExitHandler() {
	zerolog.FatalExitFunc = func() { Exit(1) }
}

func Exit(code int) {
	StopShortcutListeners()
	os.Exit(code)
}

func StopShortcutListeners() {
	if err := shortcuts.stop(); err != nil {
		log.Error().Err(err).Msg("Failed restoring keyboard terminal")
	}
}

func (t *shortcutTerminal) start() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.session != nil {
		return nil
	}
	// #nosec G115 -- runtime-owned terminal descriptors fit into int.
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil
	}
	input, err := openShortcutInput()
	if err != nil {
		return err
	}
	restore, err := makeShortcutRaw(input)
	if err != nil {
		return errors.Join(fmt.Errorf("enable keyboard raw mode: %w", err), input.Close())
	}
	session := &shortcutSession{input: input, restore: restore}
	t.session = session
	go t.listen(session)
	return nil
}

func (t *shortcutTerminal) stop() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closeLocked()
}

func (t *shortcutTerminal) closeLocked() error {
	if t.session == nil {
		return nil
	}
	session := t.session
	t.session = nil
	return errors.Join(session.restore(), session.input.Close())
}

func (t *shortcutTerminal) listen(session *shortcutSession) {
	var buf [256]byte
	for {
		n, err := session.input.Read(buf[:])
		// Ignore reads unblocked by closing a previous session.
		t.mu.Lock()
		if t.session != session {
			t.mu.Unlock()
			return
		}
		t.mu.Unlock()
		if err != nil || handleShortcut(string(buf[:n])) {
			t.mu.Lock()
			var closeErr error
			if t.session == session {
				closeErr = t.closeLocked()
			}
			t.mu.Unlock()
			if err != nil && !errors.Is(err, io.EOF) {
				log.Error().Err(err).Msg("Failed reading keyboard shortcuts")
			}
			if closeErr != nil {
				log.Error().Err(closeErr).Msg("Failed restoring keyboard terminal")
			}
			return
		}
	}
}
