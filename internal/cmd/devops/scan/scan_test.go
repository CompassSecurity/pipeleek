package scan

import (
	"testing"

	"github.com/CompassSecurity/pipeleek/pkg/config"
	"github.com/spf13/pflag"
)

func TestDevOpsScan_AllDefinedFlagsAreBound(t *testing.T) {
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

func TestDevOpsScanFlagBindings(t *testing.T) {
	t.Setenv("PIPELEEK_NO_CONFIG", "1")

	if err := config.InitializeViper(""); err != nil {
		t.Fatalf("InitializeViper failed: %v", err)
	}

	cmd := NewScanCmd()

	flagValues := map[string]string{
		"organization": "my-org",
		"project":      "my-project",
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

	if got := config.GetString("azure_devops.scan.organization"); got != "my-org" {
		t.Errorf("Expected azure_devops.scan.organization=%q, got %q", "my-org", got)
	}
	if got := config.GetString("azure_devops.scan.project"); got != "my-project" {
		t.Errorf("Expected azure_devops.scan.project=%q, got %q", "my-project", got)
	}
	if got := config.GetBool("azure_devops.scan.artifacts"); !got {
		t.Error("Expected azure_devops.scan.artifacts=true")
	}
	if got := config.GetBool("azure_devops.scan.owned"); !got {
		t.Error("Expected azure_devops.scan.owned=true")
	}
}

func TestDevOpsScanEnvVarBinding(t *testing.T) {
	t.Setenv("PIPELEEK_NO_CONFIG", "1")
	t.Setenv("PIPELEEK_AZURE_DEVOPS_SCAN_ORGANIZATION", "env-org")
	t.Setenv("PIPELEEK_AZURE_DEVOPS_SCAN_PROJECT", "env-project")

	if err := config.InitializeViper(""); err != nil {
		t.Fatalf("InitializeViper failed: %v", err)
	}

	cmd := NewScanCmd()

	if err := config.AutoBindFlags(cmd, map[string]string{
		"organization": "azure_devops.scan.organization",
		"project":      "azure_devops.scan.project",
	}); err != nil {
		t.Fatalf("AutoBindFlags failed: %v", err)
	}

	if got := config.GetString("azure_devops.scan.organization"); got != "env-org" {
		t.Errorf("Expected azure_devops.scan.organization=%q from env var, got %q", "env-org", got)
	}
	if got := config.GetString("azure_devops.scan.project"); got != "env-project" {
		t.Errorf("Expected azure_devops.scan.project=%q from env var, got %q", "env-project", got)
	}
}
