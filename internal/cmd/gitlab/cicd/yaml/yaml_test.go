package yaml

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

func TestNewYamlCmd(t *testing.T) {
	cmd := NewYamlCmd()
	assert.NotNil(t, cmd)
	assert.Equal(t, "yaml", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
	assert.NotNil(t, cmd.Flags().Lookup("project"))
}

func TestYamlCmd_AllDefinedFlagsAreBound(t *testing.T) {
	cmd := NewYamlCmd()
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Name == "help" {
			return
		}
		if _, ok := flagBindings[flag.Name]; !ok {
			t.Errorf("flag %q is defined but missing from flagBindings", flag.Name)
		}
	})
}
