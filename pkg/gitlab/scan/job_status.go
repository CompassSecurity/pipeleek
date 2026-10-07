package scan

import (
	"fmt"
	"strings"

	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func ParseJobStatuses(values []string) ([]gitlab.BuildStateValue, error) {
	var statuses []gitlab.BuildStateValue
	for _, value := range values {
		for _, status := range strings.Split(value, ",") {
			state := gitlab.BuildStateValue(strings.TrimSpace(status))
			switch state {
			case gitlab.Created, gitlab.WaitingForResource, gitlab.Preparing,
				gitlab.Pending, gitlab.Running, gitlab.Success, gitlab.Failed,
				gitlab.Canceled, gitlab.Skipped, gitlab.Manual, gitlab.Scheduled:
				statuses = append(statuses, state)
			default:
				return nil, fmt.Errorf("invalid job status %q; see --job-status in gitlab scan --help for allowed values", status)
			}
		}
	}
	return statuses, nil
}
