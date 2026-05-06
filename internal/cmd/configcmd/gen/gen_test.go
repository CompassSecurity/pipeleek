package gen_test

import (
	"bytes"
	"strings"
	"testing"

	cmdgen "github.com/CompassSecurity/pipeleek/internal/cmd/configcmd/gen"
)

func TestNewGenCmd(t *testing.T) {
	cmd := cmdgen.NewGenCmd()
	if cmd == nil {
		t.Fatal("Expected non-nil command")
	}

	if cmd.Use != "gen" {
		t.Errorf("Expected Use to be 'gen', got %q", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("Expected non-empty Short description")
	}

	if cmd.Long == "" {
		t.Error("Expected non-empty Long description")
	}

	if cmd.Example == "" {
		t.Error("Expected non-empty Example")
	}

	if cmd.Flags().Lookup("output") == nil {
		t.Error("Expected 'output' flag to exist")
	}
}

func TestGenCmd_OutputsToStdout(t *testing.T) {
	cmd := cmdgen.NewGenCmd()

	var buf bytes.Buffer
	cmd.SetOut(&buf)

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "common:") {
		t.Error("Expected output to contain 'common:' section")
	}
	if !strings.Contains(output, "gitlab:") {
		t.Error("Expected output to contain 'gitlab:' section")
	}
	if !strings.Contains(output, "hit_timeout") {
		t.Error("Expected output to contain 'hit_timeout'")
	}
}
