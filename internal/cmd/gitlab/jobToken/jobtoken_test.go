package jobtoken

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewJobTokenRootCmd(t *testing.T) {
	cmd := NewJobTokenRootCmd()
	require.NotNil(t, cmd, "NewJobTokenRootCmd should return non-nil command")

	assert.Equal(t, "jobToken", cmd.Use)
	assert.NotEmpty(t, cmd.Short, "Short description should not be empty")
	assert.NotEmpty(t, cmd.Long, "Long description should not be empty")

	flags := cmd.PersistentFlags()
	urlFlag := flags.Lookup("url")
	assert.NotNil(t, urlFlag, "'url' persistent flag should be registered")
	assert.Equal(t, "", urlFlag.DefValue, "'url' flag default should be empty")

	tokenFlag := flags.Lookup("token")
	assert.NotNil(t, tokenFlag, "'token' persistent flag should be registered")
	assert.Equal(t, "", tokenFlag.DefValue, "'token' flag default should be empty")

	foundExploit := false
	for _, sub := range cmd.Commands() {
		if sub.Use == "exploit" {
			foundExploit = true
			break
		}
	}
	assert.True(t, foundExploit, "jobToken command should have 'exploit' subcommand")
}

func TestJobTokenCmd_AllDefinedFlagsAreBound(t *testing.T) {
cmd := NewJobTokenRootCmd()
cmd.PersistentFlags().VisitAll(func(flag *pflag.Flag) {
if flag.Name == "help" {
return
}
if _, ok := flagBindings[flag.Name]; !ok {
t.Errorf("persistent flag %q is defined but missing from flagBindings", flag.Name)
}
})
}
