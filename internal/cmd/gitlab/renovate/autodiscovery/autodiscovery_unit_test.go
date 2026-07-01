package autodiscovery

import (
	"reflect"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

func TestGLNewAutodiscoveryCmd(t *testing.T) {
	cmd := NewAutodiscoveryCmd()
	assert.NotNil(t, cmd)
	assert.Equal(t, "autodiscovery", cmd.Name())
	assert.Contains(t, cmd.Short, "PoC")
}

func TestGLAutodiscoveryCmdFlags(t *testing.T) {
	cmd := NewAutodiscoveryCmd()

	tests := []struct {
		name     string
		flagName string
	}{
		{"project-name flag exists", "project-name"},
		{"username flag exists", "username"},
		{"add-renovate-cicd-for-debugging flag exists", "add-renovate-cicd-for-debugging"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := cmd.Flags().Lookup(tt.flagName)
			assert.NotNil(t, flag, "Flag %s should exist", tt.flagName)
		})
	}
}

func TestGLAutodiscoveryCmdHasRun(t *testing.T) {
	cmd := NewAutodiscoveryCmd()
	assert.Equal(t, reflect.ValueOf(RunAutodiscovery).Pointer(), reflect.ValueOf(cmd.Run).Pointer())
}

func TestGLAutodiscoveryCmdShorthandsAndBindings(t *testing.T) {
	cmd := NewAutodiscoveryCmd()
	assert.Equal(t, "p", cmd.Flags().Lookup("project-name").Shorthand)
	assert.Equal(t, "n", cmd.Flags().Lookup("username").Shorthand)

	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Name == "help" {
			return
		}
		if _, ok := flagBindings[flag.Name]; !ok {
			t.Errorf("flag %q is defined but missing from flagBindings", flag.Name)
		}
	})
}

func TestGLAutodiscoveryCmdUsernameShorthandAvoidsURLCollision(t *testing.T) {
	cmd := NewAutodiscoveryCmd()
	assert.NotEqual(t, "u", cmd.Flags().Lookup("username").Shorthand)
}
