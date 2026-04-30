package snippets

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSnippetsRootCmd(t *testing.T) {
	cmd := NewSnippetsRootCmd()

	require.NotNil(t, cmd)
	assert.Equal(t, "snippets", cmd.Use)
	assert.NotEmpty(t, cmd.Short)

	scanCmd, _, err := cmd.Find([]string{"scan"})
	require.NoError(t, err)
	require.NotNil(t, scanCmd)
	assert.Equal(t, "scan", scanCmd.Use)
}
