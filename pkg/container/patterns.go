package container

import (
	"regexp"
)

// DefaultPatterns returns the default dangerous patterns to detect in Dockerfiles
func DefaultPatterns() []Pattern {
	return []Pattern{
		{
			Name:        "copy_all_to_root",
			Pattern:     regexp.MustCompile(`(?i)^COPY\s+\./?(\s+/\s*)?$`),
			Severity:    "high",
			Description: "Copies entire working directory to root - exposes all files including secrets",
		},
		{
			Name:        "copy_all_anywhere",
			Pattern:     regexp.MustCompile(`(?i)^COPY\s+(\./?|\*|\.\/\*|\.\*)(\s+|$)`),
			Severity:    "high",
			Description: "Copies entire working directory into container - may expose sensitive files",
		},
		{
			Name:        "add_all_to_root",
			Pattern:     regexp.MustCompile(`(?i)^ADD\s+\./?(\s+/\s*)?$`),
			Severity:    "high",
			Description: "Adds entire working directory to root - exposes all files including secrets",
		},
		{
			Name:        "add_all_anywhere",
			Pattern:     regexp.MustCompile(`(?i)^ADD\s+(\./?|\*|\.\/\*|\.\*)(\s+|$)`),
			Severity:    "high",
			Description: "Adds entire working directory into container - may expose sensitive files",
		},
	}
}
