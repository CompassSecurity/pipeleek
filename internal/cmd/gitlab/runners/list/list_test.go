package list

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

func TestNewRunnersListCmd(t *testing.T) {
	cmd := NewRunnersListCmd()
	assert.NotNil(t, cmd)
	assert.Equal(t, "list", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
}

func TestRunnersListCmd_AllDefinedFlagsAreBound(t *testing.T) {
	cmd := NewRunnersListCmd()
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Name == "help" {
			return
		}
		if _, ok := flagBindings[flag.Name]; !ok {
			t.Errorf("flag %q is defined but missing from flagBindings", flag.Name)
		}
	})
}
