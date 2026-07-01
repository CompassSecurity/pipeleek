package variables

import (
	"reflect"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

func TestNewVariablesCommand(t *testing.T) {
	cmd := NewVariablesCommand()

	assert.NotNil(t, cmd)
	assert.Equal(t, "variables", cmd.Use)
	assert.Contains(t, cmd.Short, "Actions variables")
}

func TestVariablesCmd_RunHandlerIsNamed(t *testing.T) {
	cmd := NewVariablesCommand()
	assert.Equal(t, reflect.ValueOf(RunVariables).Pointer(), reflect.ValueOf(cmd.Run).Pointer())
}

func TestVariablesCommand_AllDefinedFlagsAreBound(t *testing.T) {
	cmd := NewVariablesCommand()
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Name == "help" {
			return
		}
		if _, ok := flagBindings[flag.Name]; !ok {
			t.Errorf("flag %q is defined but missing from flagBindings", flag.Name)
		}
	})
}
