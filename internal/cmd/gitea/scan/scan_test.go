package scan

import (
	"testing"

	"github.com/CompassSecurity/pipeleek/internal/cmd/testutil"
	"github.com/CompassSecurity/pipeleek/pkg/config"
)

func TestGiteaScan_AllDefinedFlagsAreBound(t *testing.T) {
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

	flags := cmd.Flags()
	for _, name := range []string{
		"cookie",
		"organization",
		"repository",
		"runs-limit",
		"start-run-id",
		"repo-sort",
		"repo-order",
		"artifacts",
		"owned",
		"threads",
		"secrets-verification",
		"max-artifact-size",
		"confidence",
		"hit-timeout",
	} {
		if flags.Lookup(name) == nil {
			t.Errorf("Expected flag %q to exist", name)
		}
	}
	if got := cmd.Flags().Lookup("repo-sort").DefValue; got != "updated" {
		t.Errorf("Expected default repo sort 'updated', got %q", got)
	}
	if got := cmd.Flags().Lookup("repo-order").DefValue; got != "desc" {
		t.Errorf("Expected default repo order 'desc', got %q", got)
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
		"repo-sort":    "size",
		"repo-order":   "asc",
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

	if err := config.NewCommandSetup(cmd).WithFlagBindings(flagBindings).Bind(); err != nil {
		t.Fatalf("Bind failed: %v", err)
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
	if got := config.GetString("gitea.scan.repo_sort"); got != "size" {
		t.Errorf("Expected gitea.scan.repo_sort=%q, got %q", "size", got)
	}
	if got := config.GetString("gitea.scan.repo_order"); got != "asc" {
		t.Errorf("Expected gitea.scan.repo_order=%q, got %q", "asc", got)
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

	if err := config.NewCommandSetup(cmd).WithFlagBindings(flagBindings).Bind(); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	if got := config.GetString("gitea.scan.organization"); got != "env-org" {
		t.Errorf("Expected gitea.scan.organization=%q from env var, got %q", "env-org", got)
	}
	if got := config.GetBool("gitea.scan.artifacts"); !got {
		t.Errorf("Expected gitea.scan.artifacts=true from env var, got %v", got)
	}
}

func TestRepositorySortAndOrderValidation(t *testing.T) {
	for _, value := range []string{"alpha", "created", "updated", "size", "id"} {
		if err := validateRepositorySort(value); err != nil {
			t.Errorf("expected sort %q to be accepted: %v", value, err)
		}
	}
	if err := validateRepositorySort("name"); err == nil {
		t.Error("expected unsupported repository sort to be rejected")
	}
	for _, value := range []string{"asc", "desc"} {
		if err := validateRepositoryOrder(value); err != nil {
			t.Errorf("expected order %q to be accepted: %v", value, err)
		}
	}
	if err := validateRepositoryOrder("ascending"); err == nil {
		t.Error("expected unsupported repository sort order to be rejected")
	}
}
