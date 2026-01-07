package renovate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRenovateCmdUsesPreRunNotPersistentPreRun(t *testing.T) {
	cmd := NewRenovateRootCmd()

	// Guard: ensure we use PreRun so root PersistentPreRun runs
	assert.NotNil(t, cmd.PreRun, "renovate PreRun should be set")
	assert.Nil(t, cmd.PersistentPreRun, "renovate should not set PersistentPreRun")
}
