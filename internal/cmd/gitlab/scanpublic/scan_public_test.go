package scanpublic

import (
	"testing"

	"github.com/CompassSecurity/pipeleek/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewScanPublicCmd(t *testing.T) {
	cmd := NewScanPublicCmd()

	require.NotNil(t, cmd)
	assert.Equal(t, "scan", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
	assert.Contains(t, cmd.Long, "does not require an API token")
	assert.Contains(t, cmd.Example, "gluna scan --gitlab")

	flags := cmd.Flags()
	assert.NotNil(t, flags.Lookup("search"))
	assert.NotNil(t, flags.Lookup("repo"))
	assert.NotNil(t, flags.Lookup("namespace"))
	assert.NotNil(t, flags.Lookup("job-limit"))
	assert.NotNil(t, flags.Lookup("queue"))
	assert.NotNil(t, flags.Lookup("artifacts"))
	assert.Nil(t, flags.Lookup("owned"), "'owned' flag must not be present on public scan")
	assert.NotNil(t, flags.Lookup("threads"))
	assert.NotNil(t, flags.Lookup("truffle-hog-verification"))
	assert.NotNil(t, flags.Lookup("confidence"))
	assert.NotNil(t, flags.Lookup("hit-timeout"))

	assert.Equal(t, "r", flags.Lookup("repo").Shorthand)
	assert.Equal(t, "n", flags.Lookup("namespace").Shorthand)
	assert.Equal(t, "s", flags.Lookup("search").Shorthand)
	assert.Equal(t, "j", flags.Lookup("job-limit").Shorthand)
	assert.Equal(t, "q", flags.Lookup("queue").Shorthand)

	assert.Equal(t, "0", flags.Lookup("job-limit").DefValue)
	assert.Equal(t, "", flags.Lookup("repo").DefValue)
	assert.Equal(t, "", flags.Lookup("namespace").DefValue)
	assert.Equal(t, "", flags.Lookup("search").DefValue)

	defaults := config.DefaultCommonScanOptions()
	assert.Equal(t, defaults.TruffleHogVerification, cmd.Flags().Lookup("truffle-hog-verification").DefValue == "true")
}
