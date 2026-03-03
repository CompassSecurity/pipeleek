package gitlab

import (
	"testing"

	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/enum"
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/register"
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/shodan"
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/variables"
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/vuln"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGitLabRootCmd(t *testing.T) {
	cmd := NewGitLabRootCmd()

	require.NotNil(t, cmd, "NewGitLabRootCmd should return non-nil command")
	assert.Equal(t, "gl [command]", cmd.Use)
	assert.NotEmpty(t, cmd.Short, "Short description should not be empty")
	assert.NotEmpty(t, cmd.Long, "Long description should not be empty")
	assert.Equal(t, "GitLab", cmd.GroupID)
	assert.GreaterOrEqual(t, len(cmd.Commands()), 8,
		"should have at least 8 subcommands")

	flags := cmd.PersistentFlags()
	gitlabFlag := flags.Lookup("gitlab")
	assert.NotNil(t, gitlabFlag, "'gitlab' persistent flag should be registered")
	assert.Equal(t, "", gitlabFlag.DefValue,
		"'gitlab' flag default should be empty")

	tokenFlag := flags.Lookup("token")
	assert.NotNil(t, tokenFlag, "'token' persistent flag should be registered")
	assert.Equal(t, "", tokenFlag.DefValue, "'token' flag default should be empty")
}

func TestNewVulnCmd(t *testing.T) {
	cmd := vuln.NewVulnCmd()

	require.NotNil(t, cmd, "NewVulnCmd should return non-nil command")
	assert.Equal(t, "vuln", cmd.Use)
	assert.NotEmpty(t, cmd.Short, "Short description should not be empty")
}

func TestNewVariablesCmd(t *testing.T) {
	cmd := variables.NewVariablesCmd()

	require.NotNil(t, cmd, "NewVariablesCmd should return non-nil command")
	assert.Equal(t, "variables", cmd.Use)
	assert.NotEmpty(t, cmd.Short, "Short description should not be empty")

	flags := cmd.Flags()
	assert.NotNil(t, flags.Lookup("gitlab"), "'gitlab' flag should be registered")
}

func TestNewEnumCmd(t *testing.T) {
	cmd := enum.NewEnumCmd()

	require.NotNil(t, cmd, "NewEnumCmd should return non-nil command")
	assert.Equal(t, "enum", cmd.Use)
	assert.NotEmpty(t, cmd.Short, "Short description should not be empty")
}

func TestNewRegisterCmd(t *testing.T) {
	cmd := register.NewRegisterCmd()

	require.NotNil(t, cmd, "NewRegisterCmd should return non-nil command")
	assert.Equal(t, "register", cmd.Use)
	assert.NotEmpty(t, cmd.Short, "Short description should not be empty")

	flags := cmd.Flags()
	assert.NotNil(t, flags.Lookup("username"), "'username' flag should be registered")
	assert.NotNil(t, flags.Lookup("email"), "'email' flag should be registered")
	assert.NotNil(t, flags.Lookup("password"), "'password' flag should be registered")
	assert.NotNil(t, flags.Lookup("gitlab"), "'gitlab' flag should be registered")
}

func TestNewShodanCmd(t *testing.T) {
	cmd := shodan.NewShodanCmd()

	require.NotNil(t, cmd, "NewShodanCmd should return non-nil command")
	assert.Equal(t, "shodan", cmd.Use)
	assert.NotEmpty(t, cmd.Short, "Short description should not be empty")

	flags := cmd.Flags()
	jsonFlag := flags.Lookup("json")
	assert.NotNil(t, jsonFlag, "'json' flag should be registered")
	assert.Equal(t, "", jsonFlag.DefValue, "'json' flag default should be empty string (path to Shodan JSON file)")
}
