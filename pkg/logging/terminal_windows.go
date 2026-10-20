package logging

import (
	"encoding/binary"
	"os"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/term"
)

var readConsoleInput = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReadConsoleInputW")

type windowsShortcutInput struct {
	*os.File
	done chan struct{}
	mu   sync.Mutex
}

func openShortcutInput() (shortcutInput, error) {
	f, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	return &windowsShortcutInput{File: f, done: make(chan struct{})}, nil
}

func makeShortcutRaw(input shortcutInput) (func() error, error) {
	// #nosec G115 -- runtime-owned terminal descriptors fit into int.
	fd := int(input.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		return nil, err
	}
	return func() error { return term.Restore(fd, state) }, nil
}

func (input *windowsShortcutInput) Read(p []byte) (int, error) {
	input.mu.Lock()
	defer input.mu.Unlock()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-input.done:
			return 0, os.ErrClosed
		case <-ticker.C:
		}
		var available uint32
		if err := windows.GetNumberOfConsoleInputEvents(windows.Handle(input.Fd()), &available); err != nil {
			return 0, err
		}
		if available == 0 {
			continue
		}
		// INPUT_RECORD is 20 bytes; its KEY_EVENT_RECORD starts at byte 4.
		var record [20]byte
		var read uint32
		result, _, err := readConsoleInput.Call(
			input.Fd(), uintptr(unsafe.Pointer(&record[0])), 1, uintptr(unsafe.Pointer(&read)),
		)
		if result == 0 {
			return 0, err
		}
		if read == 0 || binary.LittleEndian.Uint16(record[:2]) != 1 ||
			binary.LittleEndian.Uint32(record[4:8]) == 0 {
			continue
		}
		char := binary.LittleEndian.Uint16(record[14:16])
		if char == 0 || char > 127 {
			continue
		}
		return copy(p, []byte{byte(char)}), nil
	}
}

func (input *windowsShortcutInput) Close() error {
	// ReadConsole cannot be canceled by os.File.Close. Poll console events instead,
	// so cleanup can stop the reader before closing the handle.
	close(input.done)
	input.mu.Lock()
	defer input.mu.Unlock()
	return input.File.Close()
}
