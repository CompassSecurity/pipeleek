package logging

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestHitRegistersSink(t *testing.T) {
	previous := globalHitWriter
	defer func() { globalHitWriter = previous }()

	globalHitWriter = NewHitLevelWriter(nil)

	var got HitRecord
	RegisterHitSink(func(r HitRecord) {
		got = r
	})

	Hit().Str("ruleName", "aws-key").Str("value", "supersecret").Int("count", 2).Msg("SECRET")

	require.Equal(t, "aws-key", got.RuleName)
	require.Equal(t, "supersecret", got.Value)
	require.Equal(t, 2, got.Fields["count"])
	require.True(t, got.Time.After(time.Now().Add(-time.Second)))
}
