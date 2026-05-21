package schedule

import (
	"testing"

	"github.com/CompassSecurity/pipeleek/pkg/config"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

func TestNewScheduleCmd(t *testing.T) {
	cmd := NewScheduleCmd()
	assert.NotNil(t, cmd)
	assert.Equal(t, "schedule", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
	assert.NotNil(t, cmd.Flags().Lookup("url"))
	assert.NotNil(t, cmd.Flags().Lookup("token"))
}

func TestScheduleCmd_AllDefinedFlagsAreBound(t *testing.T) {
	cmd := NewScheduleCmd()
	// Build expected bindings (same logic as in FetchSchedules)
	expectedBindings := config.BindingsFromFlags(cmd, "gitlab", "schedule", map[string]string{
		"url": "gitlab.url",
		"token":  "gitlab.token",
	})

	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Name == "help" {
			return
		}
		if _, ok := expectedBindings[flag.Name]; !ok {
			t.Errorf("flag %q is defined but missing from expected bindings", flag.Name)
		}
	})
}
