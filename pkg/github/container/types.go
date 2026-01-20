package container

// ScanOptions contains all options for the container scan command
type ScanOptions struct {
	GitHubUrl          string
	GitHubApiToken     string
	Owned              bool
	Member             bool
	Public             bool
	ProjectSearchQuery string
	Page               int
	Repository         string
	Organization       string
	OrderBy            string
	DangerousPatterns  string
}

// Finding represents a dangerous pattern found in a Dockerfile/Containerfile
type Finding struct {
	ProjectPath      string
	ProjectURL       string
	FilePath         string
	FileName         string
	MatchedPattern   string
	LineContent      string
	PatternSeverity  string
	HasDockerignore  bool
	IsMultistage     bool
	RegistryMetadata *RegistryMetadata
}

// RegistryMetadata contains information about the most recent container image in the registry
type RegistryMetadata struct {
	TagName    string
	LastUpdate string
}
