package container

import "regexp"

// Finding represents a dangerous pattern found in a Dockerfile/Containerfile
type Finding struct {
	ProjectPath      string
	ProjectURL       string
	FilePath         string
	FileName         string
	MatchedPattern   string
	LineContent      string
	IsMultistage     bool
	RegistryMetadata *RegistryMetadata
}

// RegistryMetadata contains information about the most recent container image in the registry
type RegistryMetadata struct {
	TagName    string
	LastUpdate string
}

// Pattern represents a dangerous pattern to detect
type Pattern struct {
	Name        string
	Pattern     *regexp.Regexp
	Description string
}
