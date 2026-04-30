package scan

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewScanCmd(t *testing.T) {
	cmd := NewScanCmd()

	require.NotNil(t, cmd)
	assert.Equal(t, "scan", cmd.Use)
	assert.NotEmpty(t, cmd.Short)

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
}
