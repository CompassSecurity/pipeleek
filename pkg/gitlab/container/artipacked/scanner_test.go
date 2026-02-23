package artipacked

import (
	"bytes"
	"testing"

	sharedcontainer "github.com/CompassSecurity/pipeleek/pkg/container"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
)

func TestLogFinding_DoesNotEmitRegistryCreatedAt(t *testing.T) {
	originalLogger := log.Logger
	defer func() { log.Logger = originalLogger }()

	var output bytes.Buffer
	log.Logger = zerolog.New(&output)

	logFinding(sharedcontainer.Finding{
		ProjectURL:    "https://gitlab.example.com/group/project",
		FilePath:      "Dockerfile",
		LineContent:   "COPY . .",
		IsMultistage:  true,
		LatestCIRunAt: "23 Feb 2026 07:30",
		RegistryMetadata: &sharedcontainer.RegistryMetadata{
			TagName:    "latest",
			LastUpdate: "23 Feb 2026 07:29",
		},
	})

	raw := output.String()
	assert.Contains(t, raw, "latest_ci_run_at")
	assert.Contains(t, raw, "registry_tag")
	assert.Contains(t, raw, "registry_last_update")
	assert.NotContains(t, raw, "registry_created_at")
}
