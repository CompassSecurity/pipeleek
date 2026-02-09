package artipacked

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
	MinAccessLevel     int
}
