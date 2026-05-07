package variables

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

func TestNewVariablesCmd(t *testing.T) {
	cmd := NewVariablesCmd()
	assert.NotNil(t, cmd)
	assert.Equal(t, "variables", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
	assert.NotNil(t, cmd.Flags().Lookup("url"))
	assert.NotNil(t, cmd.Flags().Lookup("token"))
}

func TestVariablesCmd_AllDefinedFlagsAreBound(t *testing.T) {
	cmd := NewVariablesCmd()
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Name == "help" {
			return
		}
		if _, ok := flagBindings[flag.Name]; !ok {
			t.Errorf("flag %q is defined but missing from flagBindings", flag.Name)
		}
	})
}
