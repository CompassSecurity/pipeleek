package scan

import (
	"testing"

	"github.com/CompassSecurity/pipeleek/pkg/config"
	"github.com/spf13/pflag"
)

func TestGiteaScan_AllDefinedFlagsAreBound(t *testing.T) {
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
		t.Fatal("Expected non-nil command")
	}

	if cmd.Use != "scan" {
		t.Errorf("Expected Use to be 'scan', got %q", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("Expected non-empty Short description")
	}

	flags := cmd.Flags()
	for _, name := range []string{
		"cookie",
		"organization",
		"repository",
		"runs-limit",
		"start-run-id",
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

func TestGiteaScanFlagBindings(t *testing.T) {
	t.Setenv("PIPELEEK_NO_CONFIG", "1")

	if err := config.InitializeViper(""); err != nil {
		t.Fatalf("InitializeViper failed: %v", err)
	}

	cmd := NewScanCmd()

	flagValues := map[string]string{
		"organization": "my-org",
		"repository":   "my-repo",
	}
	for flag, value := range flagValues {
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

	if err := config.AutoBindFlags(cmd, flagBindings); err != nil {
		t.Fatalf("AutoBindFlags failed: %v", err)
	}

	if got := config.GetString("gitea.scan.organization"); got != "my-org" {
		t.Errorf("Expected gitea.scan.organization=%q, got %q", "my-org", got)
	}
	if got := config.GetString("gitea.scan.repository"); got != "my-repo" {
		t.Errorf("Expected gitea.scan.repository=%q, got %q", "my-repo", got)
	}
	if got := config.GetBool("gitea.scan.artifacts"); !got {
		t.Error("Expected gitea.scan.artifacts=true")
	}
	if got := config.GetBool("gitea.scan.owned"); !got {
		t.Error("Expected gitea.scan.owned=true")
	}
}

func TestGiteaScanEnvVarBinding(t *testing.T) {
	t.Setenv("PIPELEEK_NO_CONFIG", "1")
	t.Setenv("PIPELEEK_GITEA_SCAN_ORGANIZATION", "env-org")
	t.Setenv("PIPELEEK_GITEA_SCAN_ARTIFACTS", "true")

	if err := config.InitializeViper(""); err != nil {
		t.Fatalf("InitializeViper failed: %v", err)
	}

	cmd := NewScanCmd()

	if err := config.AutoBindFlags(cmd, flagBindings); err != nil {
		t.Fatalf("AutoBindFlags failed: %v", err)
	}

	if got := config.GetString("gitea.scan.organization"); got != "env-org" {
		t.Errorf("Expected gitea.scan.organization=%q from env var, got %q", "env-org", got)
	}
	if got := config.GetBool("gitea.scan.artifacts"); !got {
		t.Errorf("Expected gitea.scan.artifacts=true from env var, got %v", got)
	}
}
