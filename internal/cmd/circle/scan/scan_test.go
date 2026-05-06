package scan

import (
	"testing"

	"github.com/CompassSecurity/pipeleek/pkg/config"
	"github.com/spf13/pflag"
)

func TestCircleScan_AllDefinedFlagsAreBound(t *testing.T) {
	cmd := NewScanCmd()

	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Name == "help" {
			return
		}
		if _, ok := flagBindings[flag.Name]; !ok {
			t.Errorf("flag %q is defined but missing from flagBindings", flag.Name)
		}
	})
}

func TestNewScanCmd(t *testing.T) {
	cmd := NewScanCmd()
	if cmd == nil {
		t.Fatal("expected non-nil command")
	}

	if cmd.Use != "scan" {
		t.Fatalf("expected use 'scan', got %q", cmd.Use)
	}

	flags := cmd.Flags()
	for _, name := range []string{
		"token",
		"circle",
		"org",
		"project",
		"vcs",
		"branch",
		"status",
		"workflow",
		"job",
		"since",
		"until",
		"max-pipelines",
		"tests",
		"insights",
		"threads",
		"truffle-hog-verification",
		"confidence",
		"artifacts",
		"max-artifact-size",
	} {
		if flags.Lookup(name) == nil {
			t.Errorf("expected flag %q to exist", name)
		}
	}
}

func TestCircleScanFlagBindings(t *testing.T) {
	t.Setenv("PIPELEEK_NO_CONFIG", "1")

	if err := config.InitializeViper(""); err != nil {
		t.Fatalf("InitializeViper failed: %v", err)
	}

	cmd := NewScanCmd()

	if err := cmd.Flags().Set("org", "my-org"); err != nil {
		t.Fatalf("Failed to set org flag: %v", err)
	}
	if err := cmd.Flags().Set("project", "owner/repo"); err != nil {
		t.Fatalf("Failed to set project flag: %v", err)
	}
	if err := cmd.Flags().Set("artifacts", "true"); err != nil {
		t.Fatalf("Failed to set artifacts flag: %v", err)
	}

	if err := config.AutoBindFlags(cmd, flagBindings); err != nil {
		t.Fatalf("AutoBindFlags failed: %v", err)
	}

	if got := config.GetString("circle.scan.org"); got != "my-org" {
		t.Errorf("Expected circle.scan.org=%q, got %q", "my-org", got)
	}
	if got := config.GetStringSlice("circle.scan.project"); len(got) != 1 || got[0] != "owner/repo" {
		t.Errorf("Expected circle.scan.project=%q, got %v", "owner/repo", got)
	}
	if got := config.GetBool("circle.scan.artifacts"); !got {
		t.Error("Expected circle.scan.artifacts=true")
	}
}

func TestCircleScanEnvVarBinding(t *testing.T) {
	t.Setenv("PIPELEEK_NO_CONFIG", "1")
	t.Setenv("PIPELEEK_CIRCLE_SCAN_ORG", "env-org")
	t.Setenv("PIPELEEK_CIRCLE_SCAN_ARTIFACTS", "true")

	if err := config.InitializeViper(""); err != nil {
		t.Fatalf("InitializeViper failed: %v", err)
	}

	cmd := NewScanCmd()

	if err := config.AutoBindFlags(cmd, map[string]string{
		"org":       "circle.scan.org",
		"artifacts": "circle.scan.artifacts",
	}); err != nil {
		t.Fatalf("AutoBindFlags failed: %v", err)
	}

	if got := config.GetString("circle.scan.org"); got != "env-org" {
		t.Errorf("Expected circle.scan.org=%q from env var, got %q", "env-org", got)
	}
	if got := config.GetBool("circle.scan.artifacts"); !got {
		t.Errorf("Expected circle.scan.artifacts=true from env var, got %v", got)
	}
}
