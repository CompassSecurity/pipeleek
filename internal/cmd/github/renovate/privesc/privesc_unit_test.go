package privesc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewPrivescCmd(t *testing.T) {
	cmd := NewPrivescCmd()
	assert.NotNil(t, cmd)
	assert.Equal(t, "privesc", cmd.Name())
	assert.Contains(t, cmd.Short, "malicious workflow job")
}

func TestPrivescCmdFlags(t *testing.T) {
	cmd := NewPrivescCmd()

	tests := []struct {
		name     string
		flagName string
	}{
		{"repo-name flag exists", "repo-name"},
		{"renovate-branches-regex flag exists", "renovate-branches-regex"},
		{"monitoring-interval flag exists", "monitoring-interval"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := cmd.Flags().Lookup(tt.flagName)
			assert.NotNil(t, flag, "Flag %s should exist", tt.flagName)
		})
	}
}

func TestPrivescCmdMonitoringIntervalFlagDefaults(t *testing.T) {
	cmd := NewPrivescCmd()
	monitoringIntervalFlag := cmd.Flags().Lookup("monitoring-interval")
	assert.NotNil(t, monitoringIntervalFlag)
	// Check default value
	defaultValue := monitoringIntervalFlag.DefValue
	assert.Equal(t, "1s", defaultValue, "monitoring-interval should default to 1s")
}

func TestPrivescCmdHasRun(t *testing.T) {
	cmd := NewPrivescCmd()
	assert.NotNil(t, cmd.Run, "Privesc command should have Run function")
}
