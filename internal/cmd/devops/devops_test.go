package devops

import (
	"testing"

	"github.com/CompassSecurity/pipeleek/internal/cmd/devops/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAzureDevOpsRootCmd(t *testing.T) {
	cmd := NewAzureDevOpsRootCmd()

	require.NotNil(t, cmd, "NewAzureDevOpsRootCmd should return non-nil command")
	assert.Equal(t, "ad [command]", cmd.Use)
	assert.NotEmpty(t, cmd.Short, "Short description should not be empty")
	assert.Equal(t, "AzureDevOps", cmd.GroupID)
	assert.GreaterOrEqual(t, len(cmd.Commands()), 1, "should have at least 1 subcommand")

	scanCmd := cmd.Commands()[0]
	assert.Equal(t, "scan [no options!]", scanCmd.Use)
}

func TestNewScanCmd(t *testing.T) {
	cmd := scan.NewScanCmd()

	require.NotNil(t, cmd, "NewScanCmd should return non-nil command")
	assert.Equal(t, "scan [no options!]", cmd.Use)
	assert.NotEmpty(t, cmd.Short, "Short description should not be empty")
	assert.NotEmpty(t, cmd.Long, "Long description should not be empty")
	assert.NotEmpty(t, cmd.Example, "Example should not be empty")

	flags := cmd.Flags()

	tokenFlag := flags.Lookup("token")
	assert.NotNil(t, tokenFlag, "'token' flag should be registered")
	assert.Equal(t, "", tokenFlag.DefValue, "'token' flag default should be empty")
	assert.Equal(t, "t", tokenFlag.Shorthand, "'token' flag shorthand should be 't'")

	orgFlag := flags.Lookup("organization")
	assert.NotNil(t, orgFlag, "'organization' flag should be registered")
	assert.Equal(t, "", orgFlag.DefValue, "'organization' flag default should be empty")

	projectFlag := flags.Lookup("project")
	assert.NotNil(t, projectFlag, "'project' flag should be registered")
	assert.Equal(t, "", projectFlag.DefValue, "'project' flag default should be empty")

	devopsFlag := flags.Lookup("devops")
	assert.NotNil(t, devopsFlag, "'devops' flag should be registered")
	assert.Equal(t, "https://dev.azure.com", devopsFlag.DefValue,
		"'devops' flag default should be https://dev.azure.com")

	maxBuildsFlag := flags.Lookup("max-builds")
	assert.NotNil(t, maxBuildsFlag, "'max-builds' flag should be registered")
	assert.Equal(t, "-1", maxBuildsFlag.DefValue, "'max-builds' flag default should be -1")

	assert.NotNil(t, flags.Lookup("confidence"), "'confidence' flag should be registered")
	assert.NotNil(t, flags.Lookup("threads"), "'threads' flag should be registered")
	assert.NotNil(t, flags.Lookup("truffle-hog-verification"), "'truffle-hog-verification' flag should be registered")
	assert.NotNil(t, flags.Lookup("max-artifact-size"), "'max-artifact-size' flag should be registered")
}
