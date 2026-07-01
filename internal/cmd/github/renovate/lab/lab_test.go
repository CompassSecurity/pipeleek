package lab

import (
	"reflect"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

func TestNewLabCmd(t *testing.T) {
	cmd := NewLabCmd()

	assert.NotNil(t, cmd)
	assert.Equal(t, "lab", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
	assert.NotEmpty(t, cmd.Long)
	assert.NotEmpty(t, cmd.Example)
	assert.Equal(t, reflect.ValueOf(RunLabSetupCommand).Pointer(), reflect.ValueOf(cmd.Run).Pointer())
}

func TestLabCmdFlags(t *testing.T) {
	cmd := NewLabCmd()

	flag := cmd.Flags().Lookup("repo-name")
	assert.NotNil(t, flag)
	assert.Equal(t, "r", flag.Shorthand)
}

func TestLabCmd_AllDefinedFlagsAreBound(t *testing.T) {
	cmd := NewLabCmd()
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Name == "help" {
			return
		}
		if _, ok := flagBindings[flag.Name]; !ok {
			t.Errorf("flag %q is defined but missing from flagBindings", flag.Name)
		}
	})
}
