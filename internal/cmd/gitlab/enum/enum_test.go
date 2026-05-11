package enum

import (
	"testing"

	"github.com/CompassSecurity/pipeleek/internal/cmd/testutil"
	"github.com/stretchr/testify/assert"
)

func TestNewEnumCmd(t *testing.T) {
	cmd := NewEnumCmd()
	assert.NotNil(t, cmd)
	assert.Equal(t, "enum", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
	assert.NotNil(t, cmd.Flags().Lookup("url"))
	assert.NotNil(t, cmd.Flags().Lookup("token"))
	assert.NotNil(t, cmd.Flags().Lookup("level"))
}

func TestEnumCmd_AllDefinedFlagsAreBound(t *testing.T) {
	cmd := NewEnumCmd()
	testutil.AssertAllFlagsHaveBindings(t, cmd, flagBindings)
}
