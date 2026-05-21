package get_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	configcmd "github.com/CompassSecurity/pipeleek/internal/cmd/configcmd"
	"github.com/CompassSecurity/pipeleek/pkg/config"
	"github.com/spf13/cobra"
)

func extractZerologMessage(out string) string {
	for _, line := range strings.Split(out, "\n") {
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(line), &m); err == nil {
			if msg, ok := m["message"].(string); ok {
				return msg
			}
		}
	}
	return strings.TrimSpace(out)
}

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

func TestGetCmd_LegacyKeyAliasFromDefaults(t *testing.T) {
	config.ResetViper()
	t.Setenv("PIPELEEK_NO_CONFIG", "1")

	root := newRootWithConfig()
	root.SetArgs([]string{"config", "get", "common.truffle_hog_verification"})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)

	err := root.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if extractZerologMessage(out.String()) != "true" {
		t.Fatalf("expected output true, got %q", out.String())
	}
}

func TestGetCmd_SectionPathFromFile(t *testing.T) {
	config.ResetViper()
	t.Setenv("PIPELEEK_NO_CONFIG", "")

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "pipeleek.yaml")
	if err := os.WriteFile(cfgPath, []byte("gitlab:\n  token: test-token\n"), 0o644); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	root := newRootWithConfig()
	root.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		_ = config.InitializeViper(cfgPath)
	}

	root.SetArgs([]string{"config", "get", "gitlab"})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)

	if err := root.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "token: test-token") {
		t.Fatalf("expected section output to contain token, got %q", output)
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
	gl.PersistentFlags().StringVarP(&gitlabURL, "url", "u", "https://gitlab.example.com", "GitLab instance URL")
	gl.PersistentFlags().StringVarP(&token, "token", "t", "", "GitLab token")
	scanCmd := &cobra.Command{Use: "scan"}
	var threads int
	var truffleHogVerification bool
	scanCmd.Flags().IntVar(&threads, "threads", 4, "threads")
	scanCmd.Flags().BoolVar(&truffleHogVerification, "truffle-hog-verification", true, "trufflehog verification")
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
