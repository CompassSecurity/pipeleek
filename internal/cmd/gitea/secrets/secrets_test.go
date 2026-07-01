package secrets

import (
	"reflect"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

func TestSecretsCmd_AllDefinedFlagsAreBound(t *testing.T) {
	cmd := NewSecretsCommand()
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Name == "help" {
			return
		}
		if _, ok := flagBindings[flag.Name]; !ok {
			t.Errorf("flag %q is defined but missing from flagBindings", flag.Name)
		}
	})
}

func TestNewSecretsCommand(t *testing.T) {
	cmd := NewSecretsCommand()

	assert.NotNil(t, cmd)
	assert.Equal(t, "secrets", cmd.Use)
	assert.Contains(t, cmd.Short, "Actions secrets")
}

func TestSecretsCmd_RunHandlerIsNamed(t *testing.T) {
	cmd := NewSecretsCommand()
	assert.Equal(t, reflect.ValueOf(RunSecrets).Pointer(), reflect.ValueOf(cmd.Run).Pointer())
}
