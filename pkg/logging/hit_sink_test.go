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
	unregister := RegisterHitSink(func(r HitRecord) {
		got = r
	})
	defer unregister()

	Hit().Str("ruleName", "aws-key").Str("value", "supersecret").Int("count", 2).Msg("SECRET")

	require.Equal(t, "aws-key", got.RuleName)
	require.Equal(t, "supersecret", got.Value)
	require.Equal(t, 2, got.Fields["count"])
	require.True(t, got.Time.After(time.Now().Add(-time.Second)))
}

func TestHitSinkUnregisterOnlyRemovesItsSubscription(t *testing.T) {
	firstCalls := 0
	secondCalls := 0
	unregisterFirst := RegisterHitSink(func(HitRecord) { firstCalls++ })
	unregisterSecond := RegisterHitSink(func(HitRecord) { secondCalls++ })
	defer unregisterSecond()

	unregisterFirst()
	dispatchHitRecord(HitRecord{})
	require.Equal(t, 0, firstCalls)
	require.Equal(t, 1, secondCalls)

	unregisterSecond()
	dispatchHitRecord(HitRecord{})
	require.Equal(t, 1, secondCalls)
}
