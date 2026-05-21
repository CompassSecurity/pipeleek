package artipacked

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

func TestNewGHArtipackedCmd(t *testing.T) {
	cmd := NewArtipackedCmd()
	assert.NotNil(t, cmd)
	assert.Equal(t, "artipacked", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
	assert.NotNil(t, cmd.Flags().Lookup("repo"))
	assert.NotNil(t, cmd.Flags().Lookup("organization"))
	assert.NotNil(t, cmd.Flags().Lookup("search"))
	assert.NotNil(t, cmd.Flags().Lookup("page"))
	assert.NotNil(t, cmd.Flags().Lookup("order-by"))
}

func TestGHArtipackedCmd_AllDefinedFlagsAreBound(t *testing.T) {
	cmd := NewArtipackedCmd()
	// Check local flags
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Name == "help" {
			return
		}
		if _, ok := flagBindings[flag.Name]; !ok {
			t.Errorf("flag %q is defined but missing from flagBindings", flag.Name)
		}
	})
	// Check persistent flags (owned, member, public)
	cmd.PersistentFlags().VisitAll(func(flag *pflag.Flag) {
		if flag.Name == "help" {
			return
		}
		if _, ok := flagBindings[flag.Name]; !ok {
			t.Errorf("persistent flag %q is defined but missing from flagBindings", flag.Name)
		}
	})
}
