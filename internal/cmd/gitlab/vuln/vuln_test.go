package vuln

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

func TestNewVulnCmd(t *testing.T) {
	cmd := NewVulnCmd()
	assert.NotNil(t, cmd)
	assert.Equal(t, "vuln", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
	assert.NotNil(t, cmd.Flags().Lookup("url"))
	assert.NotNil(t, cmd.Flags().Lookup("token"))
}

func TestVulnCmd_AllDefinedFlagsAreBound(t *testing.T) {
	cmd := NewVulnCmd()
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Name == "help" {
			return
		}
		if _, ok := flagBindings[flag.Name]; !ok {
			t.Errorf("flag %q is defined but missing from flagBindings", flag.Name)
		}
	})
}
