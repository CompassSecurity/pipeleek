package logging_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/internal/cmd/common"
	"github.com/CompassSecurity/pipeleek/pkg/logging"
	"github.com/CompassSecurity/pipeleek/pkg/system"
	"github.com/containerd/console"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

func TestTerminalLifecycle(t *testing.T) {
	for _, mode := range []string{"normal", "error", "fatal-console", "fatal-json", "fatal-logfile", "graceful", "concurrent"} {
		t.Run(mode, func(t *testing.T) {
			for attempt := 0; attempt < 3; attempt++ {
				master, slavePath, err := console.NewPty()
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, master.Close()) })
				slave, err := os.OpenFile(slavePath, os.O_RDWR, 0)
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, slave.Close()) })
				// #nosec G115 -- runtime-owned terminal descriptors fit into int.
				fd := int(slave.Fd())
				before, err := term.GetState(fd)
				require.NoError(t, err)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestTerminalLifecycleHelper$")
				child.Env = append(os.Environ(), "PIPELEEK_TERMINAL_TEST="+mode)
				var logPath string
				if mode == "fatal-logfile" {
					logPath = filepath.Join(t.TempDir(), "fatal.log")
					child.Env = append(child.Env, "PIPELEEK_TERMINAL_LOGFILE="+logPath)
				}
				child.Stdin = slave
				child.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
				var output bytes.Buffer
				child.Stdout = &output
				child.Stderr = &output
				err = child.Run()
				require.NoError(t, ctx.Err(), output.String())
				if mode == "error" || strings.HasPrefix(mode, "fatal-") {
					var exitErr *exec.ExitError
					require.ErrorAs(t, err, &exitErr, output.String())
					require.Equal(t, 1, exitErr.ExitCode(), output.String())
				} else {
					require.NoError(t, err, output.String())
				}
				require.Contains(t, output.String(), "RAW_READY")
				if mode == "fatal-console" || mode == "fatal-json" {
					require.Contains(t, output.String(), "terminal regression fatal")
				}
				if mode == "fatal-logfile" {
					content, err := os.ReadFile(logPath)
					require.NoError(t, err)
					require.Contains(t, string(content), "terminal regression fatal")
				}
				after, err := term.GetState(fd)
				require.NoError(t, err)
				require.Equal(t, before, after, "terminal changed after %s exit", mode)
			}
		})
	}
}

func TestTerminalLifecycleHelper(t *testing.T) {
	mode := os.Getenv("PIPELEEK_TERMINAL_TEST")
	if mode == "" {
		return
	}
	common.JsonLogoutput = mode == "fatal-json"
	if mode == "fatal-logfile" {
		common.LogFile = os.Getenv("PIPELEEK_TERMINAL_LOGFILE")
	}
	root := &cobra.Command{Use: "terminal-test", RunE: runTerminalLifecycleHelper}
	common.SetupPersistentPreRun(root)
	root.SetArgs([]string{})
	common.Run(root)
	if mode == "fatal-logfile" {
		t.Fatal("fatal log returned instead of exiting")
	}
}

func runTerminalLifecycleHelper(cmd *cobra.Command, args []string) error {
	// #nosec G115 -- runtime-owned terminal descriptors fit into int.
	state, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TCGETS)
	if err != nil {
		return err
	}
	if state.Lflag&(unix.ECHO|unix.ICANON) != 0 {
		return errors.New("shortcut startup returned before raw mode was ready")
	}
	if state.Oflag&unix.OPOST == 0 {
		return errors.New("keyboard raw mode disabled log newline processing")
	}
	fmt.Println("RAW_READY")
	switch mode := os.Getenv("PIPELEEK_TERMINAL_TEST"); {
	case mode == "error":
		return errors.New("terminal regression command error")
	case strings.HasPrefix(mode, "fatal-"):
		log.Fatal().Msg("terminal regression fatal")
	case mode == "graceful":
		system.RegisterGracefulShutdownHandler(func() {})
		if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
			return err
		}
		select {}
	case mode == "concurrent":
		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(2)
			go func() {
				defer wg.Done()
				logging.ShortcutListeners(nil)
			}()
			go func() {
				defer wg.Done()
				logging.StopShortcutListeners()
			}()
		}
		wg.Wait()
	}
	return nil
}
