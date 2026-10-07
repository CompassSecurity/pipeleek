package scan

import (
	"testing"

	"github.com/stretchr/testify/assert"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func TestParsePipelineSource(t *testing.T) {
	for _, source := range []gitlab.PipelineSource{
		"", gitlab.PipelineSourceAPI, gitlab.PipelineSourceChat,
		gitlab.PipelineSourceExternal, gitlab.PipelineSourceExternalPullRequestEvent,
		gitlab.PipelineSourceMergeRequestEvent, gitlab.PipelineSourceOndemandDastScan,
		gitlab.PipelineSourceOndemandDastValidation, gitlab.PipelineSourceParentPipeline,
		gitlab.PipelineSourcePipeline, gitlab.PipelineSourcePush, gitlab.PipelineSourceSchedule,
		gitlab.PipelineSourceSecurityOrchestrationPolicy, gitlab.PipelineSourceTrigger,
		gitlab.PipelineSourceWeb, gitlab.PipelineSourceWebIDE,
	} {
		t.Run(string(source), func(t *testing.T) {
			got, err := ParsePipelineSource(string(source))
			assert.NoError(t, err)
			assert.Equal(t, source, got)
		})
	}
	t.Run("whitespace", func(t *testing.T) {
		got, err := ParsePipelineSource(" schedule ")
		assert.NoError(t, err)
		assert.Equal(t, gitlab.PipelineSourceSchedule, got)
	})
	for _, value := range []string{"invalid", "push,schedule", "SCHEDULE"} {
		t.Run(value, func(t *testing.T) {
			_, err := ParsePipelineSource(value)
			assert.ErrorContains(t, err, "invalid pipeline source")
		})
	}
}
