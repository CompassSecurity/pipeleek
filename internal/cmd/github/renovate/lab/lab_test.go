package lab

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewLabCmd(t *testing.T) {
	cmd := NewLabCmd()

	assert.NotNil(t, cmd)
	assert.Equal(t, "lab", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
	assert.NotEmpty(t, cmd.Long)
	assert.NotEmpty(t, cmd.Example)
}

func TestLabCmdFlags(t *testing.T) {
	cmd := NewLabCmd()

	// Check that required flag exists
	flag := cmd.Flags().Lookup("repo-name")
	assert.NotNil(t, flag)
	assert.Equal(t, "r", flag.Shorthand)
}
