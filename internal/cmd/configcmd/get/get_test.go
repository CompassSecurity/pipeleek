package get_test

import (
	"bytes"
	"strings"
	"testing"

	configcmd "github.com/CompassSecurity/pipeleek/internal/cmd/configcmd"
	"github.com/CompassSecurity/pipeleek/pkg/config"
	"github.com/spf13/cobra"
)

func TestGetCmd_InvalidPathReturnsError(t *testing.T) {
	config.ResetViper()
	t.Setenv("PIPELEEK_NO_CONFIG", "1")

	root := newRootWithConfig()
	root.SetArgs([]string{"config", "get", "gitlab.invalid_key"})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error for invalid path")
	}
	if !strings.Contains(err.Error(), "not an allowed configuration path") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetCmd_ValidPathFromDefaults(t *testing.T) {
	config.ResetViper()
	t.Setenv("PIPELEEK_NO_CONFIG", "1")

	root := newRootWithConfig()
	root.SetArgs([]string{"config", "get", "common.threads"})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)

	err := root.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.TrimSpace(out.String()) != "4" {
		t.Fatalf("expected output 4, got %q", out.String())
	}
}

func newRootWithConfig() *cobra.Command {
	root := &cobra.Command{Use: "pipeleek"}
	root.AddGroup(&cobra.Group{ID: "Config", Title: "Config"})
	root.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		_ = config.InitializeViper("")
	}
	root.AddCommand(configcmd.NewConfigRootCmd())

	gl := &cobra.Command{Use: "gl [command]"}
	var gitlabURL string
	var token string
	gl.PersistentFlags().StringVarP(&gitlabURL, "gitlab", "g", "https://gitlab.example.com", "GitLab instance URL")
	gl.PersistentFlags().StringVarP(&token, "token", "t", "", "GitLab token")
	scanCmd := &cobra.Command{Use: "scan"}
	var threads int
	scanCmd.Flags().IntVar(&threads, "threads", 4, "threads")
	gl.AddCommand(scanCmd)
	root.AddCommand(gl)

	gh := &cobra.Command{Use: "gh [command]"}
	scan := &cobra.Command{Use: "scan"}
	var org string
	scan.Flags().StringVar(&org, "org", "", "org")
	gh.AddCommand(scan)
	root.AddCommand(gh)

	return root
}
