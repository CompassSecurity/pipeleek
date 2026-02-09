package artipacked

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
