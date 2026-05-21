package scan

import (
	"os"
	"testing"

	"github.com/CompassSecurity/pipeleek/internal/cmd/testutil"
	"github.com/CompassSecurity/pipeleek/pkg/config"
)

func TestGitLabScan_AllDefinedFlagsAreBound(t *testing.T) {
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

	if cmd.Example == "" {
		t.Error("Expected non-empty Example")
	}

	flags := cmd.Flags()
	for _, name := range []string{
		"cookie",
		"search",
		"member",
		"repo",
		"namespace",
		"job-limit",
		"queue",
		"artifacts",
		"owned",
		"threads",
		"truffle-hog-verification",
		"max-artifact-size",
		"confidence",
		"hit-timeout",
	} {
		if flags.Lookup(name) == nil {
			t.Errorf("Expected flag %q to exist", name)
		}
	}
}

func TestGitLabScanFlagBindings(t *testing.T) {
	t.Setenv("PIPELEEK_NO_CONFIG", "1")

	if err := config.InitializeViper(""); err != nil {
		t.Fatalf("InitializeViper failed: %v", err)
	}

	cmd := NewScanCmd()

	// Set flag values
	flagMap := map[string]string{
		"search":    "mysearch",
		"repo":      "group/myrepo",
		"namespace": "mygroup",
		"queue":     "/tmp/queue",
	}
	for flag, value := range flagMap {
		if err := cmd.Flags().Set(flag, value); err != nil {
			t.Fatalf("Failed to set flag %q: %v", flag, err)
		}
	}
	if err := cmd.Flags().Set("artifacts", "true"); err != nil {
		t.Fatalf("Failed to set artifacts flag: %v", err)
	}
	if err := cmd.Flags().Set("owned", "true"); err != nil {
		t.Fatalf("Failed to set owned flag: %v", err)
	}
	if err := cmd.Flags().Set("member", "true"); err != nil {
		t.Fatalf("Failed to set member flag: %v", err)
	}

	// Bind flags to Viper keys (same mapping as in Scan())
	if err := config.NewCommandSetup(cmd).WithFlagBindings(flagBindings).Bind(); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	// Verify flag values are accessible via Viper keys
	if got := config.GetString("gitlab.scan.search"); got != "mysearch" {
		t.Errorf("Expected gitlab.scan.search=%q, got %q", "mysearch", got)
	}
	if got := config.GetString("gitlab.scan.repo"); got != "group/myrepo" {
		t.Errorf("Expected gitlab.scan.repo=%q, got %q", "group/myrepo", got)
	}
	if got := config.GetString("gitlab.scan.namespace"); got != "mygroup" {
		t.Errorf("Expected gitlab.scan.namespace=%q, got %q", "mygroup", got)
	}
	if got := config.GetString("gitlab.scan.queue"); got != "/tmp/queue" {
		t.Errorf("Expected gitlab.scan.queue=%q, got %q", "/tmp/queue", got)
	}
	if got := config.GetBool("gitlab.scan.artifacts"); !got {
		t.Error("Expected gitlab.scan.artifacts=true")
	}
	if got := config.GetBool("gitlab.scan.owned"); !got {
		t.Error("Expected gitlab.scan.owned=true")
	}
	if got := config.GetBool("gitlab.scan.member"); !got {
		t.Error("Expected gitlab.scan.member=true")
	}
}

func TestGitLabScanEnvVarBinding(t *testing.T) {
	t.Setenv("PIPELEEK_NO_CONFIG", "1")
	t.Setenv("PIPELEEK_GITLAB_SCAN_SEARCH", "env-search")
	t.Setenv("PIPELEEK_GITLAB_SCAN_ARTIFACTS", "true")

	if err := config.InitializeViper(""); err != nil {
		t.Fatalf("InitializeViper failed: %v", err)
	}

	cmd := NewScanCmd()

	if err := config.NewCommandSetup(cmd).WithFlagBindings(flagBindings).Bind(); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	// Verify env vars are read (flag not set, so env var should win)
	if got := config.GetString("gitlab.scan.search"); got != "env-search" {
		t.Errorf("Expected gitlab.scan.search=%q from env var, got %q", "env-search", got)
	}
	if got := config.GetBool("gitlab.scan.artifacts"); !got {
		t.Errorf("Expected gitlab.scan.artifacts=true from env var, got %v", got)
	}

	os.Unsetenv("PIPELEEK_GITLAB_SCAN_SEARCH")
	os.Unsetenv("PIPELEEK_GITLAB_SCAN_ARTIFACTS")
}
