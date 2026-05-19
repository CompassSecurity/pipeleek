package tf

import (
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/config"
	"github.com/spf13/pflag"
)

func TestTFCmd_AllDefinedFlagsAreBound(t *testing.T) {
	cmd := NewTFCmd()

	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Name == "help" {
			return
		}
		if _, ok := flagBindings[flag.Name]; !ok {
			t.Errorf("flag %q is defined but missing from flagBindings", flag.Name)
		}
	})
}

func TestTFCmdFlagBindings(t *testing.T) {
	t.Setenv("PIPELEEK_NO_CONFIG", "1")

	if err := config.InitializeViper(""); err != nil {
		t.Fatalf("InitializeViper failed: %v", err)
	}

	cmd := NewTFCmd()

	if err := cmd.Flags().Set("output-dir", "./custom"); err != nil {
		t.Fatalf("Failed to set output-dir flag: %v", err)
	}
	if err := cmd.Flags().Set("hit-timeout", "25s"); err != nil {
		t.Fatalf("Failed to set hit-timeout flag: %v", err)
	}

	if err := config.AutoBindFlags(cmd, flagBindings); err != nil {
		t.Fatalf("AutoBindFlags failed: %v", err)
	}

	if got := config.GetString("gitlab.tf.output_dir"); got != "./custom" {
		t.Errorf("Expected gitlab.tf.output_dir=%q, got %q", "./custom", got)
	}
	if got := config.GetString("common.hit_timeout"); got != "25s" {
		t.Errorf("Expected common.hit_timeout=%q, got %q", "25s", got)
	}
}

func TestTFCmdEnvVarBinding(t *testing.T) {
	t.Setenv("PIPELEEK_NO_CONFIG", "1")
	t.Setenv("PIPELEEK_GITLAB_TF_OUTPUT_DIR", "./env-dir")
	t.Setenv("PIPELEEK_COMMON_HIT_TIMEOUT", "45s")

	if err := config.InitializeViper(""); err != nil {
		t.Fatalf("InitializeViper failed: %v", err)
	}

	cmd := NewTFCmd()

	if err := config.AutoBindFlags(cmd, flagBindings); err != nil {
		t.Fatalf("AutoBindFlags failed: %v", err)
	}

	if got := config.GetString("gitlab.tf.output_dir"); got != "./env-dir" {
		t.Errorf("Expected gitlab.tf.output_dir=%q from env var, got %q", "./env-dir", got)
	}
	hitTimeoutRaw := config.GetString("common.hit_timeout")
	if hitTimeoutRaw != "45s" {
		t.Errorf("Expected common.hit_timeout=%q from env var, got %q", "45s", hitTimeoutRaw)
	}
	if _, err := time.ParseDuration(hitTimeoutRaw); err != nil {
		t.Fatalf("Expected parseable duration for common.hit_timeout, got error: %v", err)
	}
}
