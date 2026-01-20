package container

// ScanOptions contains all options for the container scan command
type ScanOptions struct {
	GitlabUrl          string
	GitlabApiToken     string
	Owned              bool
	Member             bool
	ProjectSearchQuery string
	Page               int
	Repository         string
	Namespace          string
	OrderBy            string
	DangerousPatterns  string
	MinAccessLevel     int
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
