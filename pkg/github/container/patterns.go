package container

import (
	sharedcontainer "github.com/CompassSecurity/pipeleek/pkg/container"
)

// DefaultPatterns returns the default dangerous patterns by delegating to the shared package
func DefaultPatterns() []sharedcontainer.Pattern {
	return sharedcontainer.DefaultPatterns()
}

// ParseCustomPatterns parses a comma-separated string of patterns by delegating to the shared package
func ParseCustomPatterns(patternsStr string) []sharedcontainer.Pattern {
	return sharedcontainer.ParseCustomPatterns(patternsStr)
}
