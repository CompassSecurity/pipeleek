package gen_test

import (
	"bytes"
	"strings"
	"testing"

	cmdgen "github.com/CompassSecurity/pipeleek/internal/cmd/configcmd/gen"
	"github.com/spf13/cobra"
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
	genCmd := cmdgen.NewGenCmd()

	root := &cobra.Command{Use: "pipeleek"}
	configCmd := &cobra.Command{Use: "config"}
	configCmd.AddCommand(genCmd)

	glCmd := &cobra.Command{Use: "gl [command]"}
	var gitlabURL string
	var token string
	glCmd.PersistentFlags().StringVarP(&gitlabURL, "gitlab", "g", "https://gitlab.example.com", "GitLab instance URL")
	glCmd.PersistentFlags().StringVarP(&token, "token", "t", "", "GitLab token")

	scanCmd := &cobra.Command{Use: "scan"}
	var threads int
	var hitTimeout string
	scanCmd.Flags().IntVarP(&threads, "threads", "", 4, "Threads")
	scanCmd.Flags().StringVarP(&hitTimeout, "hit-timeout", "", "60s", "Per-hit timeout")
	glCmd.AddCommand(scanCmd)

	root.AddCommand(glCmd)
	root.AddCommand(configCmd)

	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"config", "gen"})

	err := root.Execute()
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
