package scan
package scan

import (
	"reflect"
	"testing"

	"github.com/CompassSecurity/pipeleek/internal/cmd/testutil"
)

func TestScanCmd_AllDefinedFlagsAreBound(t *testing.T) {
	cmd := NewScanCmd()
	testutil.AssertAllFlagsHaveBindings(t, cmd, flagBindings, "url", "token")
}

func TestNewScanCmd(t *testing.T) {
	cmd := NewScanCmd()
	if cmd == nil {
		t.Fatal("Expected non-nil command")
	}

	if cmd.Use != "scan" {
		t.Errorf("Expected Use to be 'scan', got %q", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("Expected non-empty Short description")
	}

	if reflect.ValueOf(Scan).Pointer() != reflect.ValueOf(cmd.Run).Pointer() {
		t.Error("Expected cmd.Run to reference the Scan handler")
	}

	flags := cmd.Flags()
	for _, name := range []string{
		"search",
		"member",
		"repo",
		"namespace",
		"owned",
		"queue",
		"threads",
		"truffle-hog-verification",
		"confidence",
		"hit-timeout",
	} {
		if flags.Lookup(name) == nil {
			t.Errorf("Expected flag %q to exist", name)
		}
	}

	// This command must not scan artifacts or job logs - only CI/CD YAML.
	for _, name := range []string{"artifacts", "max-artifact-size", "job-limit", "cookie"} {
		if flags.Lookup(name) != nil {
			t.Errorf("Unexpected flag %q on CI/CD-only scan command", name)
		}
	}
}
