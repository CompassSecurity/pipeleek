package autodiscovery

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

func TestNewAutodiscoveryCmd(t *testing.T) {
	cmd := NewAutodiscoveryCmd()
	assert.NotNil(t, cmd)
	assert.Equal(t, "autodiscovery", cmd.Name())
	assert.Contains(t, cmd.Short, "PoC")
}

func TestAutodiscoveryCmdFlags(t *testing.T) {
	cmd := NewAutodiscoveryCmd()

	tests := []struct {
		name     string
		flagName string
	}{
		{"repo-name flag exists", "repo-name"},
		{"username flag exists", "username"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := cmd.Flags().Lookup(tt.flagName)
			assert.NotNil(t, flag, "Flag %s should exist", tt.flagName)
		})
	}
}

func TestAutodiscoveryCmdHasRun(t *testing.T) {
	cmd := NewAutodiscoveryCmd()
	assert.NotNil(t, cmd.Run, "Autodiscovery command should have Run function")
}

func TestGHAutodiscoveryCmd_AllDefinedFlagsAreBound(t *testing.T) {
cmd := NewAutodiscoveryCmd()
cmd.Flags().VisitAll(func(flag *pflag.Flag) {
if flag.Name == "help" {
return
}
if _, ok := flagBindings[flag.Name]; !ok {
t.Errorf("flag %q is defined but missing from flagBindings", flag.Name)
}
})
}
