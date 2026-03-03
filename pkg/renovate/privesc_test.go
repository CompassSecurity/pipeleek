package renovate

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBranchMonitor(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		expectError bool
	}{
		{
			name:        "valid renovate pattern",
			pattern:     `^renovate/`,
			expectError: false,
		},
		{
			name:        "valid complex pattern",
			pattern:     `renovate/(npm|pip|github-actions).*`,
			expectError: false,
		},
		{
			name:        "empty pattern",
			pattern:     "",
			expectError: false,
		},
		{
			name:        "invalid regex pattern",
			pattern:     `[invalid`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			monitor, err := NewBranchMonitor(tt.pattern)
			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, monitor)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, monitor)
				assert.NotNil(t, monitor.originalBranches)
				assert.NotNil(t, monitor.regex)
			}
		})
	}
}

func TestCheckBranch_FirstScan(t *testing.T) {
	monitor, err := NewBranchMonitor(`^renovate/`)
	require.NoError(t, err)

	// During first scan, all branches are recorded but not flagged
	result := monitor.CheckBranch("renovate/npm-dep", true)
	assert.False(t, result, "first scan should never return true")
	assert.True(t, monitor.originalBranches["renovate/npm-dep"], "branch should be recorded")

	result = monitor.CheckBranch("main", true)
	assert.False(t, result, "first scan should never return true for any branch")
	assert.True(t, monitor.originalBranches["main"], "branch should be recorded")
}

func TestCheckBranch_SubsequentScan_NewRenovateBranch(t *testing.T) {
	monitor, err := NewBranchMonitor(`^renovate/`)
	require.NoError(t, err)

	// First scan: record existing branches
	monitor.CheckBranch("main", true)
	monitor.CheckBranch("feature/old", true)

	// Second scan: new renovate branch appears
	result := monitor.CheckBranch("renovate/npm-jest-5.x", false)
	assert.True(t, result, "new renovate branch should be detected")
}

func TestCheckBranch_SubsequentScan_ExistingBranch(t *testing.T) {
	monitor, err := NewBranchMonitor(`^renovate/`)
	require.NoError(t, err)

	// First scan: record existing branches including a renovate one
	monitor.CheckBranch("renovate/existing", true)
	monitor.CheckBranch("main", true)

	// Second scan: existing renovate branch should not be flagged again
	result := monitor.CheckBranch("renovate/existing", false)
	assert.False(t, result, "existing branch should not be flagged")
}

func TestCheckBranch_SubsequentScan_NonMatchingBranch(t *testing.T) {
	monitor, err := NewBranchMonitor(`^renovate/`)
	require.NoError(t, err)

	// First scan
	monitor.CheckBranch("main", true)

	// Second scan: new branch that doesn't match pattern
	result := monitor.CheckBranch("feature/new-feature", false)
	assert.False(t, result, "non-matching new branch should not be flagged")
}

func TestCheckBranch_MultiplePatterns(t *testing.T) {
	monitor, err := NewBranchMonitor(`(^renovate/|^deps/update)`)
	require.NoError(t, err)

	// First scan
	monitor.CheckBranch("main", true)

	// Second scan: branches matching different parts of the pattern
	assert.True(t, monitor.CheckBranch("renovate/lodash", false))
	assert.True(t, monitor.CheckBranch("deps/update-all", false))
	assert.False(t, monitor.CheckBranch("feature/thing", false))
}

func TestGetMonitoringInterval(t *testing.T) {
	interval := GetMonitoringInterval()
	assert.Equal(t, 1*time.Second, interval)
}

func TestGetRetryInterval(t *testing.T) {
	interval := GetRetryInterval()
	assert.Equal(t, 5*time.Second, interval)
}

func TestLogExploitInstructions(t *testing.T) {
	// LogExploitInstructions only logs, ensure it doesn't panic
	assert.NotPanics(t, func() {
		LogExploitInstructions("renovate/npm-jest-5.x", "main")
	})
}

func TestValidateRepositoryName(t *testing.T) {
	tests := []struct {
		name     string
		repoName string
		expected bool
	}{
		{
			name:     "valid owner/repo format",
			repoName: "myorg/myrepo",
			expected: true,
		},
		{
			name:     "valid with deeper path",
			repoName: "myorg/myrepo/subrepo",
			expected: true,
		},
		{
			name:     "single word",
			repoName: "myrepo",
			expected: true,
		},
		{
			name:     "empty string",
			repoName: "",
			expected: false,
		},
		{
			name:     "just slash",
			repoName: "/",
			expected: false,
		},
		{
			name:     "leading slash",
			repoName: "/myorg/myrepo",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateRepositoryName(tt.repoName)
			assert.Equal(t, tt.expected, result)
		})
	}
}
