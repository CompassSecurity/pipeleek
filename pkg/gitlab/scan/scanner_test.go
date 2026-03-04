package scan

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitializeOptions_Valid(t *testing.T) {
	opts, err := InitializeOptions(
		"https://gitlab.example.com",
		"glpat-token",
		"",
		"search-query",
		"",
		"",
		"/tmp/queue",
		"500MB",
		true, false, false, true,
		100, 4,
		[]string{"high"},
		30*time.Second,
	)
	require.NoError(t, err)
	assert.Equal(t, "https://gitlab.example.com", opts.GitlabUrl)
	assert.Equal(t, "glpat-token", opts.GitlabApiToken)
	assert.Equal(t, "search-query", opts.ProjectSearchQuery)
	assert.True(t, opts.Artifacts)
	assert.False(t, opts.Owned)
	assert.Equal(t, 100, opts.JobLimit)
	assert.Equal(t, 4, opts.MaxScanGoRoutines)
	assert.Equal(t, []string{"high"}, opts.ConfidenceFilter)
	assert.Equal(t, 30*time.Second, opts.HitTimeout)
	assert.Equal(t, "/tmp/queue", opts.QueueFolder)
	assert.True(t, opts.TruffleHogVerification)
}

func TestInitializeOptions_InvalidURL(t *testing.T) {
	_, err := InitializeOptions(
		"not-a-valid-url",
		"token", "", "", "", "", "/tmp/q", "100MB",
		false, false, false, false, 0, 1, nil, 5*time.Second,
	)
	assert.Error(t, err)
}

func TestInitializeOptions_InvalidArtifactSize(t *testing.T) {
	_, err := InitializeOptions(
		"https://gitlab.example.com",
		"token", "", "", "", "", "/tmp/q", "notasize",
		false, false, false, false, 0, 1, nil, 5*time.Second,
	)
	assert.Error(t, err)
}

func TestInitializeOptions_ArtifactSizeVariants(t *testing.T) {
	tests := []struct {
		name    string
		sizeStr string
		wantErr bool
	}{
		{"MB size", "100MB", false},
		{"GB size", "1GB", false},
		{"KB size", "500KB", false},
		{"zero bytes", "0", false},
		{"invalid text", "lots", true},
		{"empty string", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := InitializeOptions(
				"https://gitlab.example.com",
				"token", "", "", "", "", "/tmp/q", tt.sizeStr,
				false, false, false, false, 0, 1, nil, 5*time.Second,
			)
			if tt.wantErr {
				assert.Error(t, err, "expected error for size=%q", tt.sizeStr)
			} else {
				assert.NoError(t, err, "expected no error for size=%q", tt.sizeStr)
			}
		})
	}
}

func TestInitializeOptions_MembersAndOwnedFlags(t *testing.T) {
	opts, err := InitializeOptions(
		"https://gitlab.example.com",
		"token", "", "", "", "", "/tmp/q", "10MB",
		false, true, true, false, 0, 1, nil, 5*time.Second,
	)
	require.NoError(t, err)
	assert.True(t, opts.Owned)
	assert.True(t, opts.Member)
}

func TestInitializeOptions_RepositoryAndNamespace(t *testing.T) {
	opts, err := InitializeOptions(
		"https://gitlab.example.com",
		"token", "", "", "org/repo", "mygroup", "/tmp/q", "10MB",
		false, false, false, false, 0, 1, nil, 5*time.Second,
	)
	require.NoError(t, err)
	assert.Equal(t, "org/repo", opts.Repository)
	assert.Equal(t, "mygroup", opts.Namespace)
}

func TestNewScanner_ReturnsScanner(t *testing.T) {
	opts := &ScanOptions{
		GitlabUrl:      "https://gitlab.example.com",
		GitlabApiToken: "token",
	}
	s := NewScanner(opts)
	assert.NotNil(t, s)
	// Before any queue is set, GetQueueStatus must return 0
	assert.Equal(t, 0, s.GetQueueStatus())
}
