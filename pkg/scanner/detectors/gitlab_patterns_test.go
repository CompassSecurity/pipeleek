package detectors

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGitLabSharedPATFormats(t *testing.T) {
	detector := NewGitLabURLDetector()
	for _, test := range []struct {
		name, token, wantName string
	}{
		{"v2", "glpat-" + strings.Repeat("a", 20), "Gitlab - Personal Access Token v2"},
		{"v3", "glpat-" + strings.Repeat("a", 27) + ".ab.123456789", "Gitlab - Personal Access Token v3"},
		{"oversized v2", "glpat-" + strings.Repeat("a", 23), ""},
		{"malformed v3", "glpat-" + strings.Repeat("a", 27) + "XabX123456789", ""},
		{"embedded prefix", "prefixglpat-" + strings.Repeat("a", 20), ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			results, err := detector.FromDataWithURL(context.Background(), false, []byte("TOKEN="+test.token+","), "")
			require.NoError(t, err)
			if test.wantName == "" {
				assert.Empty(t, results)
				return
			}
			require.Len(t, results, 1)
			assert.Equal(t, test.wantName, results[0].DetectorName)
			assert.Equal(t, test.token, string(results[0].Raw))
			assert.False(t, results[0].Verified)
		})
	}
}
