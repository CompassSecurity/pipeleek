package container

import (
	"regexp"
	"strings"
)

// IsMultistage checks if Dockerfile content uses multistage builds by counting FROM statements
func IsMultistage(content string) bool {
	lines := strings.Split(content, "\n")

	fromCount := 0
	fromPattern := regexp.MustCompile(`(?i)^\s*FROM\s+`)

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		// Skip empty lines and comments
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") {
			continue
		}

		if fromPattern.MatchString(line) {
			fromCount++
			if fromCount > 1 {
				return true
			}
		}
	}

	return false
}

// PatternMatch represents a matched pattern with details
type PatternMatch struct {
	PatternName string
	MatchedLine string
}

// ScanDockerfileForPatterns scans Dockerfile content and returns all pattern matches
func ScanDockerfileForPatterns(content string, patterns []Pattern) []PatternMatch {
	var matches []PatternMatch
	lines := strings.Split(content, "\n")

	// Check against all patterns
	for _, pattern := range patterns {
		// Search through lines to find a match
		for _, line := range lines {
			trimmedLine := strings.TrimSpace(line)
			// Skip empty lines and comments
			if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") {
				continue
			}

			if pattern.Pattern.MatchString(line) {
				matches = append(matches, PatternMatch{
					PatternName: pattern.Name,
					MatchedLine: strings.TrimSpace(line),
				})
				break // Only match once per pattern
			}
		}
	}

	return matches
}

// ScanDockerfileContent checks a Dockerfile's content against patterns and returns matched lines
// Deprecated: Use ScanDockerfileForPatterns instead
func ScanDockerfileContent(content string, patterns []Pattern) []string {
	var matches []string
	lines := strings.Split(content, "\n")

	// Check against all patterns
	for _, pattern := range patterns {
		// Search through lines to find a match
		for _, line := range lines {
			trimmedLine := strings.TrimSpace(line)
			// Skip empty lines and comments
			if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") {
				continue
			}

			if pattern.Pattern.MatchString(line) {
				matches = append(matches, strings.TrimSpace(line))
				break
			}
		}
	}

	return matches
}

// ScanDockerfileForPattern checks if a Dockerfile matches a specific pattern
func ScanDockerfileForPattern(content string, pattern Pattern) bool {
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		// Skip empty lines and comments
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") {
			continue
		}

		if pattern.Pattern.MatchString(line) {
			return true
		}
	}

	return false
}
