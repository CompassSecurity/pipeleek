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
			status = strings.TrimSpace(status)
			if status == "" {
				return nil, fmt.Errorf("invalid job status %q; see --job-status in gitlab scan --help for allowed values", status)
			}
			statuses = append(statuses, gitlab.BuildStateValue(status))
		}
	}
	return statuses, nil
}
