package register

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

func TestNewRegisterCmd(t *testing.T) {
	cmd := NewRegisterCmd()
	assert.NotNil(t, cmd)
	assert.Equal(t, "register", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
	assert.NotNil(t, cmd.Flags().Lookup("gitlab"))
	assert.NotNil(t, cmd.Flags().Lookup("username"))
	assert.NotNil(t, cmd.Flags().Lookup("password"))
	assert.NotNil(t, cmd.Flags().Lookup("email"))
}

func TestRegisterCmd_AllDefinedFlagsAreBound(t *testing.T) {
	cmd := NewRegisterCmd()
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Name == "help" {
			return
		}
		if _, ok := flagBindings[flag.Name]; !ok {
			t.Errorf("flag %q is defined but missing from flagBindings", flag.Name)
		}
	})
}
