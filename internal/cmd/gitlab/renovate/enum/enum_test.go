package enum

import (
	"reflect"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

func TestNewGLRenovateEnumCmd(t *testing.T) {
	cmd := NewEnumCmd()
	assert.NotNil(t, cmd)
	assert.NotEmpty(t, cmd.Short)
	assert.NotNil(t, cmd.Flags().Lookup("repo"))
	assert.NotNil(t, cmd.Flags().Lookup("namespace"))
	assert.NotNil(t, cmd.Flags().Lookup("search"))
	assert.NotNil(t, cmd.Flags().Lookup("fast"))
	assert.NotNil(t, cmd.Flags().Lookup("dump"))
	assert.NotNil(t, cmd.Flags().Lookup("page"))
	assert.NotNil(t, cmd.Flags().Lookup("order-by"))
	assert.NotNil(t, cmd.Flags().Lookup("extend-renovate-config-service"))
	assert.Equal(t, "r", cmd.Flags().Lookup("repo").Shorthand)
	assert.Equal(t, "", cmd.Flags().Lookup("page").Shorthand)
	assert.Equal(t, reflect.ValueOf(RunEnumerate).Pointer(), reflect.ValueOf(cmd.Run).Pointer())
}

func TestGLRenovateEnumCmd_AllDefinedFlagsAreBound(t *testing.T) {
	cmd := NewEnumCmd()
	// Check local flags
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Name == "help" {
			return
		}
		if _, ok := flagBindings[flag.Name]; !ok {
			t.Errorf("flag %q is defined but missing from flagBindings", flag.Name)
		}
	})
	// Check persistent flags (owned, member)
	cmd.PersistentFlags().VisitAll(func(flag *pflag.Flag) {
		if flag.Name == "help" {
			return
		}
		if _, ok := flagBindings[flag.Name]; !ok {
			t.Errorf("persistent flag %q is defined but missing from flagBindings", flag.Name)
		}
	})
}
