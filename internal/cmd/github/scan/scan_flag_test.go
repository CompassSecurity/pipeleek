package scan

import (
	"testing"

	"github.com/CompassSecurity/pipeleek/internal/cmd/testutil"
	"github.com/CompassSecurity/pipeleek/pkg/config"
)

func TestGitHubScan_AllDefinedFlagsAreBound(t *testing.T) {
	cmd := NewScanCmd()
	testutil.AssertAllFlagsHaveBindings(t, cmd, flagBindings)
}

func TestGitHubScanFlagBindings(t *testing.T) {
	t.Setenv("PIPELEEK_NO_CONFIG", "1")

	if err := config.InitializeViper(""); err != nil {
		t.Fatalf("InitializeViper failed: %v", err)
	}

	cmd := NewScanCmd()

	flagValues := map[string]string{
		"org":    "my-org",
		"user":   "my-user",
		"search": "security",
		"repo":   "owner/repo",
	}
	for flag, value := range flagValues {
		if err := cmd.Flags().Set(flag, value); err != nil {
			t.Fatalf("Failed to set flag %q: %v", flag, err)
		}
	}
	if err := cmd.Flags().Set("public", "true"); err != nil {
		t.Fatalf("Failed to set public flag: %v", err)
	}
	if err := cmd.Flags().Set("artifacts", "true"); err != nil {
		t.Fatalf("Failed to set artifacts flag: %v", err)
	}
	if err := cmd.Flags().Set("owned", "true"); err != nil {
		t.Fatalf("Failed to set owned flag: %v", err)
	}

	if err := config.AutoBindFlags(cmd, flagBindings); err != nil {
		t.Fatalf("AutoBindFlags failed: %v", err)
	}

	if got := config.GetString("github.scan.org"); got != "my-org" {
		t.Errorf("Expected github.scan.org=%q, got %q", "my-org", got)
	}
	if got := config.GetString("github.scan.user"); got != "my-user" {
		t.Errorf("Expected github.scan.user=%q, got %q", "my-user", got)
	}
	if got := config.GetString("github.scan.search"); got != "security" {
		t.Errorf("Expected github.scan.search=%q, got %q", "security", got)
	}
	if got := config.GetString("github.scan.repo"); got != "owner/repo" {
		t.Errorf("Expected github.scan.repo=%q, got %q", "owner/repo", got)
	}
	if got := config.GetBool("github.scan.public"); !got {
		t.Error("Expected github.scan.public=true")
	}
	if got := config.GetBool("github.scan.artifacts"); !got {
		t.Error("Expected github.scan.artifacts=true")
	}
	if got := config.GetBool("github.scan.owned"); !got {
		t.Error("Expected github.scan.owned=true")
	}
}

func TestGitHubScanEnvVarBinding(t *testing.T) {
	t.Setenv("PIPELEEK_NO_CONFIG", "1")
	t.Setenv("PIPELEEK_GITHUB_SCAN_ORG", "env-org")
	t.Setenv("PIPELEEK_GITHUB_SCAN_PUBLIC", "true")

	if err := config.InitializeViper(""); err != nil {
		t.Fatalf("InitializeViper failed: %v", err)
	}

	cmd := NewScanCmd()

	if err := config.AutoBindFlags(cmd, flagBindings); err != nil {
		t.Fatalf("AutoBindFlags failed: %v", err)
	}

	if got := config.GetString("github.scan.org"); got != "env-org" {
		t.Errorf("Expected github.scan.org=%q from env var, got %q", "env-org", got)
	}
	if got := config.GetBool("github.scan.public"); !got {
		t.Errorf("Expected github.scan.public=true from env var, got %v", got)
	}
}
