package artipacked

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
