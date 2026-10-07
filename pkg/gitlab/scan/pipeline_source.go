package scan

import (
	"fmt"
	"strings"

	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func ParsePipelineSource(value string) (gitlab.PipelineSource, error) {
	source := gitlab.PipelineSource(strings.TrimSpace(value))
	switch source {
	case "", gitlab.PipelineSourceAPI, gitlab.PipelineSourceChat,
		gitlab.PipelineSourceExternal, gitlab.PipelineSourceExternalPullRequestEvent,
		gitlab.PipelineSourceMergeRequestEvent, gitlab.PipelineSourceOndemandDastScan,
		gitlab.PipelineSourceOndemandDastValidation, gitlab.PipelineSourceParentPipeline,
		gitlab.PipelineSourcePipeline, gitlab.PipelineSourcePush, gitlab.PipelineSourceSchedule,
		gitlab.PipelineSourceSecurityOrchestrationPolicy, gitlab.PipelineSourceTrigger,
		gitlab.PipelineSourceWeb, gitlab.PipelineSourceWebIDE:
		return source, nil
	default:
		return "", fmt.Errorf("invalid pipeline source %q; see --pipeline-source in gitlab scan --help for allowed values", value)
	}
}
