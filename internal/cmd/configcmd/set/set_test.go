package set_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	configcmd "github.com/CompassSecurity/pipeleek/internal/cmd/configcmd"
	"github.com/CompassSecurity/pipeleek/pkg/config"
	"github.com/spf13/cobra"
)

func TestSetCmd_InvalidPathReturnsError(t *testing.T) {
	config.ResetViper()
	t.Setenv("PIPELEEK_NO_CONFIG", "1")

	root := newRootWithConfig()
	root.SetArgs([]string{"config", "set", "gitlab.not_real", "foo"})
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

func TestSetCmd_WritesValidPath(t *testing.T) {
	config.ResetViper()
	t.Setenv("PIPELEEK_NO_CONFIG", "")

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "pipeleek.yaml")
	if err := os.WriteFile(cfgPath, []byte("common:\n  threads: 4\n"), 0o644); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	root := newRootWithConfig()
	root.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		_ = config.InitializeViper(cfgPath)
	}

	root.SetArgs([]string{"config", "set", "common.threads", "8"})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)

	if err := root.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	updated, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read cfg: %v", err)
	}
	if !strings.Contains(string(updated), "threads") || !strings.Contains(string(updated), "8") {
		t.Fatalf("expected updated config to contain threads=8, got:\n%s", string(updated))
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
	gl.PersistentFlags().StringVarP(&gitlabURL, "url", "g", "https://gitlab.example.com", "GitLab instance URL")
	gl.PersistentFlags().StringVarP(&token, "token", "t", "", "GitLab token")
	scan := &cobra.Command{Use: "scan"}
	var search string
	var threads int
	scan.Flags().StringVar(&search, "search", "", "search")
	scan.Flags().IntVar(&threads, "threads", 4, "threads")
	gl.AddCommand(scan)
	root.AddCommand(gl)

	gh := &cobra.Command{Use: "gh [command]"}
	ghScan := &cobra.Command{Use: "scan"}
	var org string
	ghScan.Flags().StringVar(&org, "org", "", "org")
	gh.AddCommand(ghScan)
	root.AddCommand(gh)

	return root
}
