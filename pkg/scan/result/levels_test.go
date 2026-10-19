package result

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/CompassSecurity/pipeleek/pkg/logging"
	"github.com/CompassSecurity/pipeleek/pkg/scanner"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReportDetectionLevels(t *testing.T) {
	var output bytes.Buffer
	original, level := log.Logger, zerolog.GlobalLevel()
	writer := logging.NewHitLevelWriter(&output)
	log.Logger = zerolog.New(writer)
	logging.SetGlobalHitWriter(writer)
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	t.Cleanup(func() {
		log.Logger = original
		logging.SetGlobalHitWriter(nil)
		zerolog.SetGlobalLevel(level)
	})
	for _, confidence := range []string{"verified", "trufflehog"} {
		output.Reset()
		ReportFinding(scanner.Finding{
			Pattern: scanner.PatternElement{Pattern: scanner.PatternPattern{Name: "fixture", Confidence: confidence}},
			Text:    "fixture-value",
			Engine:  "trufflehog",
		}, ReportOptions{})
		var record map[string]interface{}
		require.NoError(t, json.Unmarshal(output.Bytes(), &record))
		assert.Equal(t, confidence, record["confidence"])
		assert.Equal(t, "trufflehog", record["engine"])
	}
}
