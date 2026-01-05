package renovate

import (
	"regexp"
	"time"

	"github.com/rs/zerolog/log"
)

// BranchMonitor provides common branch monitoring functionality for Renovate exploit detection
type BranchMonitor struct {
	originalBranches map[string]bool
	regex            *regexp.Regexp
}

// NewBranchMonitor creates a new branch monitor with the given regex pattern
func NewBranchMonitor(pattern string) (*BranchMonitor, error) {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	return &BranchMonitor{
		originalBranches: make(map[string]bool),
		regex:            regex,
	}, nil
}

// CheckBranch checks if a branch name matches the Renovate pattern and is new
func (bm *BranchMonitor) CheckBranch(branchName string, isFirstScan bool) bool {
	if isFirstScan {
		bm.originalBranches[branchName] = true
		return false
	}

	// If branch existed before, skip it
	if _, exists := bm.originalBranches[branchName]; exists {
		return false
	}

	// Check if it matches the Renovate pattern
	if bm.regex.MatchString(branchName) {
		log.Info().Str("branch", branchName).Msg("Identified Renovate Bot branch")
		return true
	}

	return false
}

// GetMonitoringInterval returns the recommended polling interval for branch monitoring
func GetMonitoringInterval() time.Duration {
	return 10 * time.Second
}

// GetRetryInterval returns the recommended retry interval on errors
func GetRetryInterval() time.Duration {
	return 5 * time.Second
}

// LogExploitInstructions logs common instructions for the privilege escalation exploit
func LogExploitInstructions(branchName string, defaultBranch string) {
	log.Info().Str("branch", branchName).Msg("CI/CD configuration updated, check if we won the race!")
	log.Info().Msg("If Renovate automatically merges the branch, you have successfully exploited the privilege escalation vulnerability")
	log.Info().Str("defaultBranch", defaultBranch).Msg("The injected job will run on the default branch after merge")
}

// ValidateRepositoryName validates the repository/project name format (owner/repo)
func ValidateRepositoryName(repoName string) bool {
	// Basic validation - should contain at least one slash
	// More sophisticated validation can be added as needed
	return len(repoName) > 0 && repoName != "/"
}
