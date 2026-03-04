package jobtoken

import (
	"testing"

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
	gitlabFlag := flags.Lookup("gitlab")
	assert.NotNil(t, gitlabFlag, "'gitlab' persistent flag should be registered")
	assert.Equal(t, "", gitlabFlag.DefValue, "'gitlab' flag default should be empty")

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
