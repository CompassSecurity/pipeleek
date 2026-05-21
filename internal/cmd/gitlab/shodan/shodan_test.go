package shodan

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

func TestNewShodanCmd(t *testing.T) {
	cmd := NewShodanCmd()
	assert.NotNil(t, cmd)
	assert.Equal(t, "shodan", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
	assert.NotNil(t, cmd.Flags().Lookup("json"))
}

func TestShodanCmd_AllDefinedFlagsAreBound(t *testing.T) {
	cmd := NewShodanCmd()
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Name == "help" {
			return
		}
		if _, ok := flagBindings[flag.Name]; !ok {
			t.Errorf("flag %q is defined but missing from flagBindings", flag.Name)
		}
	})
}
