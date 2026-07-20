package whoami

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

func TestNewWhoAmICmd(t *testing.T) {
	cmd := NewWhoAmICmd()

	assert.NotNil(t, cmd)
	assert.Equal(t, "whoami", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
	assert.NotNil(t, cmd.Flags().Lookup("url"))
	assert.NotNil(t, cmd.Flags().Lookup("token"))
}

func TestWhoAmICmd_AllDefinedFlagsAreBound(t *testing.T) {
	cmd := NewWhoAmICmd()
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Name == "help" {
			return
		}
		if _, ok := flagBindings[flag.Name]; !ok {
			t.Errorf("flag %q is defined but missing from flagBindings", flag.Name)
		}
	})
}
