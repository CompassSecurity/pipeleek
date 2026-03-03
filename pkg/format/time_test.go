package format

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParseISO8601(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected time.Time
	}{
		{
			name:     "valid RFC3339 UTC",
			input:    "2023-01-15T10:30:00Z",
			expected: time.Date(2023, 1, 15, 10, 30, 0, 0, time.UTC),
		},
		{
			name:  "valid RFC3339 with positive timezone offset",
			input: "2023-01-15T10:30:00+01:00",
			expected: func() time.Time {
				loc := time.FixedZone("", 3600)
				return time.Date(2023, 1, 15, 10, 30, 0, 0, loc)
			}(),
		},
		{
			name:  "valid RFC3339 with negative timezone offset",
			input: "2023-01-15T10:30:00-05:00",
			expected: func() time.Time {
				loc := time.FixedZone("", -18000)
				return time.Date(2023, 1, 15, 10, 30, 0, 0, loc)
			}(),
		},
		{
			name:     "start of epoch",
			input:    "1970-01-01T00:00:00Z",
			expected: time.Unix(0, 0).UTC(),
		},
		{
			name:     "end of year",
			input:    "2023-12-31T23:59:59Z",
			expected: time.Date(2023, 12, 31, 23, 59, 59, 0, time.UTC),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := ParseISO8601(tt.input)
			assert.True(t, result.Equal(tt.expected),
				"ParseISO8601(%q) = %v, want %v", tt.input, result, tt.expected)
		})
	}
}
