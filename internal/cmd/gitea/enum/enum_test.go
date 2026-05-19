package enum

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

func TestNewGitEaEnumCmd(t *testing.T) {
	cmd := NewEnumCmd()
	assert.NotNil(t, cmd)
	assert.Equal(t, "enum", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
}

func TestGiteaEnumCmd_AllDefinedFlagsAreBound(t *testing.T) {
	cmd := NewEnumCmd()
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Name == "help" {
			return
		}
		if _, ok := flagBindings[flag.Name]; !ok {
			t.Errorf("flag %q is defined but missing from flagBindings", flag.Name)
		}
	})
}
