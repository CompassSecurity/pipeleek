package schedule

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

func TestNewScheduleCmd(t *testing.T) {
	cmd := NewScheduleCmd()
	assert.NotNil(t, cmd)
	assert.Equal(t, "schedule", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
	assert.NotNil(t, cmd.Flags().Lookup("gitlab"))
	assert.NotNil(t, cmd.Flags().Lookup("token"))
}

func TestScheduleCmd_AllDefinedFlagsAreBound(t *testing.T) {
	cmd := NewScheduleCmd()
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Name == "help" {
			return
		}
		if _, ok := flagBindings[flag.Name]; !ok {
			t.Errorf("flag %q is defined but missing from flagBindings", flag.Name)
		}
	})
}
