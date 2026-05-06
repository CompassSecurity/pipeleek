package scan

import (
	"testing"

	"github.com/CompassSecurity/pipeleek/pkg/config"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewScanCmd(t *testing.T) {
	cmd := NewScanCmd()

	require.NotNil(t, cmd)
	assert.Equal(t, "scan", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
	assert.Contains(t, cmd.Long, "including public ones")
	assert.Contains(t, cmd.Example, "--project")
	assert.Contains(t, cmd.Example, "--namespace")

	flags := cmd.Flags()
	assert.NotNil(t, flags.Lookup("project"))
	assert.NotNil(t, flags.Lookup("namespace"))
	assert.NotNil(t, flags.Lookup("search"))
	assert.NotNil(t, flags.Lookup("owned"))
	assert.NotNil(t, flags.Lookup("member"))
	assert.NotNil(t, flags.Lookup("threads"))
	assert.NotNil(t, flags.Lookup("truffle-hog-verification"))
	assert.NotNil(t, flags.Lookup("confidence"))
	assert.NotNil(t, flags.Lookup("hit-timeout"))

	assert.Equal(t, "p", flags.Lookup("project").Shorthand)
	assert.Equal(t, "n", flags.Lookup("namespace").Shorthand)
	assert.Equal(t, "s", flags.Lookup("search").Shorthand)
	assert.Equal(t, "o", flags.Lookup("owned").Shorthand)
	assert.Equal(t, "m", flags.Lookup("member").Shorthand)

	assert.Equal(t, "false", flags.Lookup("owned").DefValue)
	assert.Equal(t, "false", flags.Lookup("member").DefValue)
	assert.Equal(t, "", flags.Lookup("project").DefValue)
	assert.Equal(t, "", flags.Lookup("namespace").DefValue)
	assert.Equal(t, "", flags.Lookup("search").DefValue)

	defaults := config.DefaultCommonScanOptions()
	assert.Equal(t, defaults.TruffleHogVerification, cmd.Flags().Lookup("truffle-hog-verification").DefValue == "true")
}

func TestSnippetsScanCmd_AllDefinedFlagsAreBound(t *testing.T) {
cmd := NewScanCmd()
cmd.Flags().VisitAll(func(flag *pflag.Flag) {
if flag.Name == "help" {
return
}
if _, ok := flagBindings[flag.Name]; !ok {
t.Errorf("flag %q is defined but missing from flagBindings", flag.Name)
}
})
}
