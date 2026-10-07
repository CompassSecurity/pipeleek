package scan

import (
	"testing"

	"github.com/stretchr/testify/assert"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func TestParseJobStatuses(t *testing.T) {
	tests := []struct {
		name   string
		input  []string
		want   []gitlab.BuildStateValue
		errMsg string
	}{
		{name: "no filter"},
		{name: "empty list", input: []string{}},
		{name: "multiple", input: []string{"success", "failed"}, want: []gitlab.BuildStateValue{gitlab.Success, gitlab.Failed}},
		{name: "comma separated", input: []string{"success, failed"}, want: []gitlab.BuildStateValue{gitlab.Success, gitlab.Failed}},
		{
			name:  "all supported statuses",
			input: []string{"created", "waiting_for_resource", "preparing", "pending", "running", "success", "failed", "canceled", "skipped", "manual", "scheduled"},
			want:  []gitlab.BuildStateValue{gitlab.Created, gitlab.WaitingForResource, gitlab.Preparing, gitlab.Pending, gitlab.Running, gitlab.Success, gitlab.Failed, gitlab.Canceled, gitlab.Skipped, gitlab.Manual, gitlab.Scheduled},
		},
		{name: "invalid", input: []string{"success", "failure"}, errMsg: `invalid job status "failure"`},
		{name: "empty status", input: []string{""}, errMsg: `invalid job status ""`},
		{name: "trailing comma", input: []string{"success,"}, errMsg: `invalid job status ""`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseJobStatuses(tt.input)
			if tt.errMsg != "" {
				assert.ErrorContains(t, err, tt.errMsg)
				assert.Nil(t, got)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
