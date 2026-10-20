//go:build !windows

package logging

import (
	"errors"
	"os"
	"syscall"

	"github.com/containerd/console"
)

func openShortcutInput() (shortcutInput, error) {
	// Nonblocking open lets Go's poller interrupt the read when cleanup closes it.
	return os.OpenFile("/dev/tty", os.O_RDONLY|syscall.O_NONBLOCK, 0)
}

func makeShortcutRaw(input shortcutInput) (func() error, error) {
	c, err := console.ConsoleFromFile(input)
	if err != nil {
		return nil, err
	}
	// console.SetRaw preserves output processing, so log newlines stay aligned.
	if err := c.SetRaw(); err != nil {
		return nil, errors.Join(err, c.Reset())
	}
	return c.Reset, nil
}
