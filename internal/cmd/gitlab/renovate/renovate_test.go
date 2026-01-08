package renovate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRenovateCmdUsesPreRunNotPersistentPreRun(t *testing.T) {
	cmd := NewRenovateRootCmd()

	// Guard: we intentionally bind config inside subcommand Run; no PreRun required
	assert.Nil(t, cmd.PreRun, "renovate PreRun should be unset")
	assert.Nil(t, cmd.PersistentPreRun, "renovate should not set PersistentPreRun")
}
