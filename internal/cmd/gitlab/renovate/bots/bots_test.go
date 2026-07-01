package bots

import (
	"reflect"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

func TestNewBotsCmd(t *testing.T) {
	cmd := NewBotsCmd()
	assert.NotNil(t, cmd)
	assert.Equal(t, "bots", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
	assert.NotNil(t, cmd.Flags().Lookup("term"))
	assert.Equal(t, reflect.ValueOf(RunBots).Pointer(), reflect.ValueOf(cmd.Run).Pointer())
}

func TestBotsCmd_AllDefinedFlagsAreBound(t *testing.T) {
	cmd := NewBotsCmd()
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Name == "help" {
			return
		}
		if _, ok := flagBindings[flag.Name]; !ok {
			t.Errorf("flag %q is defined but missing from flagBindings", flag.Name)
		}
	})
}
