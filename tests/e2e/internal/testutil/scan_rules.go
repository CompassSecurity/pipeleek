package testutil

import (
	_ "embed"
	"os"
	"testing"
)

//go:embed testdata/scan-rules.yaml
var scanRules []byte

// UseTestRules isolates transport/pipeline tests from downloaded rule databases
// and provider verification. Detection policy is tested separately.
func UseTestRules(t *testing.T) {
	t.Helper()
	t.Chdir(t.TempDir())
	t.Setenv("PIPELEEK_COMMON_SECRETS_VERIFICATION", "false")
	if err := os.WriteFile("rules.yml", scanRules, 0600); err != nil {
		t.Fatalf("write scan fixture rules: %v", err)
	}
}
