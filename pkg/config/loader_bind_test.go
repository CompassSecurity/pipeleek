package config

import (
	"testing"

	"github.com/spf13/cobra"
)

// resetViper resets the global viper instance for tests.
func resetViper(t *testing.T) {
	t.Helper()
	globalViper = nil
	if err := InitializeViper(""); err != nil {
		t.Fatalf("failed to init viper: %v", err)
	}
}

func TestBindCommandFlags_LocalFlags(t *testing.T) {
	resetViper(t)

	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("my-flag", "default", "")

	if err := BindCommandFlags(cmd, "gitlab.scan", nil); err != nil {
		t.Fatalf("bind failed: %v", err)
	}

	if err := cmd.Flags().Set("my-flag", "cli-value"); err != nil {
		t.Fatalf("set flag: %v", err)
	}

	if got := GetViper().GetString("gitlab.scan.my_flag"); got != "cli-value" {
		t.Fatalf("expected cli-value, got %q", got)
	}
}

func TestBindCommandFlags_Overrides(t *testing.T) {
	resetViper(t)

	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("gitlab", "https://example.com", "")

	if err := BindCommandFlags(cmd, "gitlab.scan", map[string]string{"gitlab": "gitlab.url"}); err != nil {
		t.Fatalf("bind failed: %v", err)
	}

	if err := cmd.Flags().Set("gitlab", "https://override.example.com"); err != nil {
		t.Fatalf("set flag: %v", err)
	}

	if got := GetViper().GetString("gitlab.url"); got != "https://override.example.com" {
		t.Fatalf("expected override value, got %q", got)
	}
}

func TestBindCommandFlags_InheritedFlags(t *testing.T) {
	resetViper(t)

	root := &cobra.Command{Use: "root"}
	root.PersistentFlags().String("token", "", "")

	child := &cobra.Command{Use: "child"}
	root.AddCommand(child)

	if err := BindCommandFlags(child, "gitlab.enum", map[string]string{"token": "gitlab.token"}); err != nil {
		t.Fatalf("bind failed: %v", err)
	}

	if err := root.PersistentFlags().Set("token", "from-root"); err != nil {
		t.Fatalf("set flag: %v", err)
	}

	if got := GetViper().GetString("gitlab.token"); got != "from-root" {
		t.Fatalf("expected inherited flag value, got %q", got)
	}
}
