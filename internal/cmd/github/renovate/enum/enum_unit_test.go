package enum

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewEnumCmd(t *testing.T) {
	cmd := NewEnumCmd()
	assert.NotNil(t, cmd)
	assert.Equal(t, "enum", cmd.Name())
	assert.Equal(t, "Enumerate Renovate configurations", cmd.Short)
}

func TestEnumCmdFlags(t *testing.T) {
	cmd := NewEnumCmd()

	tests := []struct {
		name     string
		flagName string
	}{
		{"owned flag exists", "owned"},
		{"member flag exists", "member"},
		{"repo flag exists", "repo"},
		{"org flag exists", "org"},
		{"search flag exists", "search"},
		{"fast flag exists", "fast"},
		{"dump flag exists", "dump"},
		{"page flag exists", "page"},
		{"order-by flag exists", "order-by"},
		{"extend-renovate-config-service flag exists", "extend-renovate-config-service"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := cmd.Flags().Lookup(tt.flagName)
			assert.NotNil(t, flag, "Flag %s should exist", tt.flagName)
		})
	}
}

func TestEnumCmdHasPreRun(t *testing.T) {
	cmd := NewEnumCmd()
	assert.NotNil(t, cmd.PreRun, "Enum command should have PreRun hook")
}

func TestEnumCmdHasRun(t *testing.T) {
	cmd := NewEnumCmd()
	assert.NotNil(t, cmd.Run, "Enum command should have Run function")
}
