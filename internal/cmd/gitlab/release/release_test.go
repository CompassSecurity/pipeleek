package release

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewReleaseRootCmd(t *testing.T) {
	cmd := NewReleaseRootCmd()
	scan, args, err := cmd.Find([]string{"scan"})
	require.NoError(t, err)
	require.Empty(t, args)
	assert.Equal(t, "scan", scan.Name())
	assert.NotNil(t, scan.Run)
}
