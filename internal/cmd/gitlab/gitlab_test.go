package gitlab

import (
	"testing"

	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/enum"
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/register"
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/scanpublic"
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/shodan"
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/snippets"
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
	urlFlag := flags.Lookup("url")
	assert.NotNil(t, urlFlag, "'url' persistent flag should be registered")
	assert.Equal(t, "", urlFlag.DefValue,
		"'url' flag default should be empty")

	tokenFlag := flags.Lookup("token")
	assert.NotNil(t, tokenFlag, "'token' persistent flag should be registered")
	assert.Equal(t, "", tokenFlag.DefValue, "'token' flag default should be empty")

	snippetsCmd, _, err := cmd.Find([]string{"snippets"})
	require.NoError(t, err)
	require.NotNil(t, snippetsCmd)
	assert.Equal(t, "snippets", snippetsCmd.Name())
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
	assert.NotNil(t, flags.Lookup("url"), "'url' flag should be registered")
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
	assert.NotNil(t, flags.Lookup("url"), "'url' flag should be registered")
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

func TestNewSnippetsRootCmd(t *testing.T) {
	cmd := snippets.NewSnippetsRootCmd()

	require.NotNil(t, cmd, "NewSnippetsRootCmd should return non-nil command")
	assert.Equal(t, "snippets", cmd.Use)
	assert.NotEmpty(t, cmd.Short, "Short description should not be empty")

	scanCmd, _, err := cmd.Find([]string{"scan"})
	require.NoError(t, err)
	require.NotNil(t, scanCmd)
	assert.Equal(t, "scan", scanCmd.Name())
}

func TestNewGitLabRootUnauthenticatedCmd(t *testing.T) {
	cmd := NewGitLabRootUnauthenticatedCmd()

	require.NotNil(t, cmd)
	assert.Equal(t, "gluna [command]", cmd.Use)
	assert.Equal(t, "Helper", cmd.GroupID)

	shodanCmd, _, err := cmd.Find([]string{"shodan"})
	require.NoError(t, err)
	assert.NotNil(t, shodanCmd)

	registerCmd, _, err := cmd.Find([]string{"register"})
	require.NoError(t, err)
	assert.NotNil(t, registerCmd)

	publicScanCmd, _, err := cmd.Find([]string{"scan"})
	require.NoError(t, err)
	assert.NotNil(t, publicScanCmd)
}

func TestNewScanPublicCmd(t *testing.T) {
	cmd := scanpublic.NewScanPublicCmd()

	require.NotNil(t, cmd)
	assert.Equal(t, "scan", cmd.Use)
	assert.NotEmpty(t, cmd.Short)

	flags := cmd.Flags()
	assert.NotNil(t, flags.Lookup("repo"), "'repo' flag should be registered")
	assert.NotNil(t, flags.Lookup("namespace"), "'namespace' flag should be registered")
	assert.NotNil(t, flags.Lookup("search"), "'search' flag should be registered")
}
