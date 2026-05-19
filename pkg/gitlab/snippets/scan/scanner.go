package scan

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/gitlab/util"
	"github.com/CompassSecurity/pipeleek/pkg/httpclient"
	"github.com/CompassSecurity/pipeleek/pkg/scan/result"
	"github.com/CompassSecurity/pipeleek/pkg/scan/runner"
	pkgscanner "github.com/CompassSecurity/pipeleek/pkg/scanner"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

type ScanOptions struct {
	GitlabURL              string
	GitlabToken            string
	Project                string
	Namespace              string
	ProjectSearchQuery     string
	Owned                  bool
	Member                 bool
	MaxScanGoRoutines      int
	TruffleHogVerification bool
	ConfidenceFilter       []string
	HitTimeout             time.Duration
}

type Scanner interface {
	pkgscanner.BaseScanner
	Status() *zerolog.Event
}

type snippetsScanner struct {
	options           *ScanOptions
	lastSnippetID     atomic.Int64
	processedSnippets atomic.Int64
}

var _ pkgscanner.BaseScanner = (*snippetsScanner)(nil)

func NewScanner(opts *ScanOptions) Scanner {
	return &snippetsScanner{options: opts}
}

func InitializeOptions(gitlabURL, gitlabToken, project, namespace, projectSearchQuery string,
	owned, member bool, maxScanGoRoutines int, truffleHogVerification bool,
	confidenceFilter []string, hitTimeout time.Duration) (*ScanOptions, error) {

	if _, err := url.ParseRequestURI(gitlabURL); err != nil {
		return nil, err
	}

	if project != "" && namespace != "" {
		return nil, fmt.Errorf("--project and --group are mutually exclusive")
	}

	return &ScanOptions{
		GitlabURL:              gitlabURL,
		GitlabToken:            gitlabToken,
		Project:                project,
		Namespace:              namespace,
		ProjectSearchQuery:     projectSearchQuery,
		Owned:                  owned,
		Member:                 member,
		MaxScanGoRoutines:      maxScanGoRoutines,
		TruffleHogVerification: truffleHogVerification,
		ConfidenceFilter:       confidenceFilter,
		HitTimeout:             hitTimeout,
	}, nil
}

func (s *snippetsScanner) Scan() error {
	runner.InitScanner(s.options.ConfidenceFilter)

	git, err := util.GetGitlabClient(s.options.GitlabToken, s.options.GitlabURL)
	if err != nil {
		return fmt.Errorf("failed creating gitlab client: %w", err)
	}

	switch {
	case s.options.Project != "":
		return s.scanProjectByPath(git, s.options.Project)
	case s.options.Namespace != "":
		return s.scanNamespace(git, s.options.Namespace)
	case s.options.Owned || s.options.Member || s.options.ProjectSearchQuery != "":
		return s.scanFilteredProjects(git)
	default:
		return s.scanAllVisibleSnippets(git)
	}
}

func (s *snippetsScanner) Status() *zerolog.Event {
	return log.Info().
		Int64("lastSnippetId", s.lastSnippetID.Load()).
		Int64("processedSnippets", s.processedSnippets.Load())
}

func (s *snippetsScanner) markSnippetProcessed(snippetID int64) {
	s.lastSnippetID.Store(snippetID)
	s.processedSnippets.Add(1)
}

// refFromRawURL extracts the git ref from a GitLab snippet raw URL.
// URL format: https://host/.../-/snippets/{id}/raw/{ref}/{filepath}
func refFromRawURL(rawURL string) string {
	const marker = "/raw/"
	idx := strings.LastIndex(rawURL, marker)
	if idx < 0 {
		return "HEAD"
	}
	rest := rawURL[idx+len(marker):]
	slashIdx := strings.Index(rest, "/")
	if slashIdx < 0 {
		return rest
	}
	return rest[:slashIdx]
}

// encodeFilePath URL-encodes a file path for use in API URLs,
// preserving segment boundaries by encoding each segment and joining with %2F.
func encodeFilePath(p string) string {
	parts := strings.Split(p, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return strings.Join(parts, "%2F")
}

func (s *snippetsScanner) fetchFileContent(apiURL string) ([]byte, error) {
	log.Debug().Str("apiURL", apiURL).Msg("Fetching snippet file content via API")

	client := httpclient.GetPipeleekHTTPClient("", nil, map[string]string{
		"PRIVATE-TOKEN": s.options.GitlabToken,
	})

	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return content, nil
}

func (s *snippetsScanner) scanProjectByPath(git *gitlab.Client, projectPath string) error {
	project, _, err := git.Projects.GetProject(projectPath, &gitlab.GetProjectOptions{})
	if err != nil {
		return fmt.Errorf("failed fetching project %q: %w", projectPath, err)
	}

	return s.scanProjectSnippets(git, project)
}

func (s *snippetsScanner) scanNamespace(git *gitlab.Client, namespace string) error {
	group, _, err := git.Groups.GetGroup(namespace, &gitlab.GetGroupOptions{})
	if err != nil {
		return fmt.Errorf("failed fetching namespace %q: %w", namespace, err)
	}

	opts := &gitlab.ListGroupProjectsOptions{
		ListOptions:      gitlab.ListOptions{PerPage: 100, Page: 1},
		OrderBy:          gitlab.Ptr("last_activity_at"),
		Owned:            gitlab.Ptr(s.options.Owned),
		Search:           gitlab.Ptr(s.options.ProjectSearchQuery),
		WithShared:       gitlab.Ptr(true),
		IncludeSubGroups: gitlab.Ptr(true),
	}

	return util.IterateGroupProjects(git, group.ID, opts, func(project *gitlab.Project) error {
		if err := s.scanProjectSnippets(git, project); err != nil {
			log.Debug().Err(err).Str("project", project.PathWithNamespace).Msg("Failed scanning project snippets, skipping")
		}
		return nil
	})
}

func (s *snippetsScanner) scanFilteredProjects(git *gitlab.Client) error {
	opts := &gitlab.ListProjectsOptions{
		ListOptions: gitlab.ListOptions{PerPage: 100, Page: 1},
		Owned:       gitlab.Ptr(s.options.Owned),
		Membership:  gitlab.Ptr(s.options.Member),
		Search:      gitlab.Ptr(s.options.ProjectSearchQuery),
		OrderBy:     gitlab.Ptr("last_activity_at"),
	}

	return util.IterateProjects(git, opts, func(project *gitlab.Project) error {
		if err := s.scanProjectSnippets(git, project); err != nil {
			log.Debug().Err(err).Str("project", project.PathWithNamespace).Msg("Failed scanning project snippets, skipping")
		}
		return nil
	})
}

func (s *snippetsScanner) scanProjectSnippets(git *gitlab.Client, project *gitlab.Project) error {
	opts := &gitlab.ListProjectSnippetsOptions{
		ListOptions: gitlab.ListOptions{PerPage: 100, Page: 1, OrderBy: "created_at", Sort: "desc"},
	}

	for {
		snippets, resp, err := git.ProjectSnippets.ListSnippets(project.ID, opts)
		if err != nil {
			status := 0
			if resp != nil {
				status = resp.StatusCode
			}
			return fmt.Errorf("failed listing project snippets for %q (status %d): %w", project.PathWithNamespace, status, err)
		}

		for _, snippet := range snippets {
			s.markSnippetProcessed(snippet.ID)

			// Scan each file in the snippet
			if len(snippet.Files) == 0 {
				// Fallback: get content via SnippetContent if no files listed
				content, resp, err := git.ProjectSnippets.SnippetContent(project.ID, snippet.ID)
				if err != nil {
					status := 0
					if resp != nil {
						status = resp.StatusCode
					}
					log.Debug().Err(err).Int64("snippetId", snippet.ID).Int("status", status).Str("project", project.PathWithNamespace).Msg("Failed fetching project snippet content, skipping")
					continue
				}

				s.reportFindings(content, snippet, "", map[string]string{
					"url":     snippet.WebURL,
					"project": project.PathWithNamespace,
				})
			} else {
				for _, file := range snippet.Files {
					ref := refFromRawURL(file.RawURL)
					apiURL := fmt.Sprintf("%s/api/v4/projects/%d/snippets/%d/files/%s/%s/raw",
						strings.TrimRight(s.options.GitlabURL, "/"),
						project.ID, snippet.ID,
						url.PathEscape(ref), encodeFilePath(file.Path))
					content, err := s.fetchFileContent(apiURL)
					if err != nil {
						log.Debug().Err(err).Int64("snippetId", snippet.ID).Str("file", file.Path).Str("ref", ref).Str("project", project.PathWithNamespace).Msg("Failed fetching project snippet file content, skipping")
						continue
					}

					s.reportFindings(content, snippet, file.Path, map[string]string{
						"url":     snippet.WebURL,
						"project": project.PathWithNamespace,
					})
				}
			}
		}

		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return nil
}

func (s *snippetsScanner) scanAllVisibleSnippets(git *gitlab.Client) error {
	opts := &gitlab.ExploreSnippetsOptions{
		ListOptions: gitlab.ListOptions{PerPage: 100, Page: 1, OrderBy: "created_at", Sort: "desc"},
	}

	for {
		snippets, resp, err := git.Snippets.ExploreSnippets(opts)
		if err != nil {
			status := 0
			if resp != nil {
				status = resp.StatusCode
			}
			return fmt.Errorf("failed listing public snippets (status %d): %w", status, err)
		}

		for _, snippet := range snippets {
			s.markSnippetProcessed(snippet.ID)

			// Scan each file in the snippet
			if len(snippet.Files) == 0 {
				// Fallback: get content via SnippetContent if no files listed
				content, resp, err := git.Snippets.SnippetContent(snippet.ID)
				if err != nil {
					status := 0
					if resp != nil {
						status = resp.StatusCode
					}
					log.Debug().Err(err).Int64("snippetId", snippet.ID).Int("status", status).Msg("Failed fetching snippet content, skipping")
					continue
				}

				s.reportFindings(content, snippet, "", map[string]string{
					"url": snippet.WebURL,
				})
			} else {
				for _, file := range snippet.Files {
					ref := refFromRawURL(file.RawURL)
					content, _, err := git.Snippets.SnippetFileContent(snippet.ID, ref, file.Path)
					if err != nil {
						log.Debug().Err(err).Int64("snippetId", snippet.ID).Str("file", file.Path).Str("ref", ref).Msg("Failed fetching snippet file content, skipping")
						continue
					}

					s.reportFindings(content, snippet, file.Path, map[string]string{
						"url": snippet.WebURL,
					})
				}
			}
		}

		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return nil
}

func (s *snippetsScanner) reportFindings(content []byte, snippet *gitlab.Snippet, filePath string, customFields map[string]string) {
	findings, err := pkgscanner.DetectHits(content, s.options.MaxScanGoRoutines, s.options.TruffleHogVerification, s.options.HitTimeout)
	if err != nil {
		log.Warn().Err(err).Int64("snippetId", snippet.ID).Str("file", filePath).Msg("Failed detecting secrets in snippet content")
		return
	}

	if len(findings) == 0 {
		return
	}

	fields := map[string]string{
		"snippetId": fmt.Sprintf("%d", snippet.ID),
		"title":     snippet.Title,
	}
	if filePath != "" {
		fields["file"] = filePath
	}
	for k, v := range customFields {
		fields[k] = v
	}

	for _, finding := range findings {
		result.ReportFindingWithCustomFields(finding, fields)
	}
}
