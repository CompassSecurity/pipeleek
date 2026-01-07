package confige2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/tests/e2e/internal/testutil"
)

// TestConfigFileLoading_Enabled verifies that when PIPELEEK_NO_CONFIG=0 and a config file exists
// under $HOME/.config/pipeleek/pipeleek.yaml, the CLI loads it and logs the file path.
func TestConfigFileLoading_Enabled(t *testing.T) {
	tmpHome, err := os.MkdirTemp("", "pipeleek-e2e-home-")
	if err != nil {
		t.Fatalf("failed to create temp home: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpHome) }()

	cfgDir := filepath.Join(tmpHome, ".config", "pipeleek")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatalf("failed to create config dir: %v", err)
	}

	cfgPath := filepath.Join(cfgDir, "pipeleek.yaml")
	cfgContent := []byte("gitlab:\n  url: http://127.0.0.1:1\n  token: glpat-test\ncommon:\n  threads: 1\n")
	if err := os.WriteFile(cfgPath, cfgContent, 0o644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	// Run a lightweight command to trigger root PersistentPreRun and config loading
	stdout, stderr, err := testutil.RunCLI(t, []string{"gl", "scan", "--owned"}, []string{"PIPELEEK_NO_CONFIG=0", "HOME=" + tmpHome}, 3*time.Second)
	_ = stderr
	_ = err // command may fail due to unreachable GitLab URL, which is fine

	if !strings.Contains(stdout, "Loaded config file") {
		t.Fatalf("expected output to contain 'Loaded config file', got:\n%s", stdout)
	}
}
