package confige2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
)

func TestConfigGet_InvalidPath(t *testing.T) {
	stdout, stderr, err := testutil.RunCLI(t, []string{"config", "get", "gitlab.not_real"}, []string{}, 40*time.Second)
	combined := stdout + "\n" + stderr
	if err == nil {
		t.Fatal("expected command to fail for invalid path")
	}
	if !strings.Contains(combined, "not an allowed configuration path") {
		t.Fatalf("expected invalid-path error, got:\n%s", combined)
	}
}

func TestConfigSet_ThenGet_RoundTrip(t *testing.T) {
	tmpHome := t.TempDir()
	cfgDir := filepath.Join(tmpHome, ".config", "pipeleek")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatalf("mkdir cfg dir: %v", err)
	}
	cfgPath := filepath.Join(cfgDir, "pipeleek.yaml")
	if err := os.WriteFile(cfgPath, []byte("common:\n  threads: 4\n"), 0o644); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	stdoutSet, stderrSet, errSet := testutil.RunCLI(
		t,
		[]string{"config", "set", "common.threads", "8"},
		[]string{"PIPELEEK_NO_CONFIG=0", "HOME=" + tmpHome},
		40*time.Second,
	)
	_ = stderrSet
	if errSet != nil {
		t.Fatalf("unexpected set error: %v\nstdout:\n%s", errSet, stdoutSet)
	}
	if !strings.Contains(stdoutSet, "Configuration updated") {
		t.Fatalf("expected update message, got:\n%s", stdoutSet)
	}

	stdoutGet, stderrGet, errGet := testutil.RunCLI(
		t,
		[]string{"config", "get", "common.threads"},
		[]string{"PIPELEEK_NO_CONFIG=0", "HOME=" + tmpHome},
		40*time.Second,
	)
	combinedGet := strings.TrimSpace(stdoutGet + "\n" + stderrGet)
	if errGet != nil {
		t.Fatalf("unexpected get error: %v\noutput:\n%s", errGet, combinedGet)
	}
	if !strings.HasSuffix(combinedGet, "8") {
		t.Fatalf("expected output to end with 8, got %q", combinedGet)
	}

	content, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read cfg: %v", err)
	}
	if !strings.Contains(string(content), "8") {
		t.Fatalf("expected cfg file updated to contain 8, got:\n%s", string(content))
	}
}
