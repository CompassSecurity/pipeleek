package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/CircleCI-Public/circleci-cli/api/rest"
	"github.com/rs/zerolog/log"
)

type CircleClient interface {
	ListOrganizationProjects(ctx context.Context, orgSlug, defaultVCS string) ([]string, error)
	ListAccessibleProjectsV1(ctx context.Context, defaultVCS, orgFilter string) ([]string, error)
	ListPipelines(ctx context.Context, projectSlug, branch, pageToken string) ([]pipelineItem, string, error)
	ListPipelineWorkflows(ctx context.Context, pipelineID string) ([]workflowItem, error)
	ListWorkflowJobs(ctx context.Context, workflowID string) ([]workflowJobItem, error)
	GetProjectJob(ctx context.Context, projectSlug string, jobNumber int) (projectJobResponse, error)
	GetProjectJobV1(ctx context.Context, projectSlug string, jobNumber int) (projectJobResponse, error)
	ListJobArtifacts(ctx context.Context, projectSlug string, jobNumber int) ([]jobArtifactItem, error)
	ListJobTests(ctx context.Context, projectSlug string, jobNumber int) ([]jobTestItem, error)
	ListProjectInsightsWorkflows(ctx context.Context, projectSlug, branch string) ([]string, error)
	GetProjectInsightsWorkflow(ctx context.Context, projectSlug, workflowName, branch string) (map[string]interface{}, error)
	DownloadWithAuth(ctx context.Context, rawURL string) ([]byte, error)
}

type circleAPIClient struct {
	restClient *rest.Client
	httpClient *http.Client
	token      string
}

func newCircleAPIClient(baseURL *url.URL, token string, httpClient *http.Client) *circleAPIClient {
	return &circleAPIClient{
		restClient: rest.New(baseURL, token, httpClient),
		httpClient: httpClient,
		token:      token,
	}
}

type pipelineListResponse struct {
	Items         []pipelineItem `json:"items"`
	NextPageToken string         `json:"next_page_token"`
}

type orgProjectListResponse struct {
	Items []struct {
		Slug string `json:"slug"`
	} `json:"items"`
	NextPageToken string `json:"next_page_token"`
}

type v1ProjectItem struct {
	Username string `json:"username"`
	Reponame string `json:"reponame"`
	VCSURL   string `json:"vcs_url"`
	VCSType  string `json:"vcs_type"`
}

type pipelineItem struct {
	ID        string `json:"id"`
	Number    int    `json:"number"`
	State     string `json:"state"`
	CreatedAt string `json:"created_at"`
}

type workflowListResponse struct {
	Items []workflowItem `json:"items"`
}

type workflowItem struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}

type workflowJobListResponse struct {
	Items []workflowJobItem `json:"items"`
}

type workflowJobItem struct {
	JobNumber int    `json:"job_number"`
	Name      string `json:"name"`
	Status    string `json:"status"`
}

type projectJobResponse struct {
	Name   string `json:"name"`
	WebURL string `json:"web_url"`
	Steps  []struct {
		Name    string `json:"name"`
		Actions []struct {
			Step      int    `json:"step"`
			Index     int    `json:"index"`
			Name      string `json:"name"`
			OutputURL string `json:"output_url"`
		} `json:"actions"`
	} `json:"steps"`
}

type jobArtifactsResponse struct {
	Items []jobArtifactItem `json:"items"`
}

type jobArtifactItem struct {
	Path string `json:"path"`
	URL  string `json:"url"`
}

type jobTestsResponse struct {
	Items []jobTestItem `json:"items"`
}

type jobTestItem struct {
	Name    string `json:"name"`
	Result  string `json:"result"`
	Message string `json:"message"`
	File    string `json:"file"`
}

func (c *circleAPIClient) ListPipelines(ctx context.Context, projectSlug, branch, pageToken string) ([]pipelineItem, string, error) {
	q := url.Values{}
	if branch != "" {
		q.Set("branch", branch)
	}
	if pageToken != "" {
		q.Set("page-token", pageToken)
	}

	var out pipelineListResponse
	if err := c.getJSON(ctx, fmt.Sprintf("project/%s/pipeline", projectSlug), q, &out); err != nil {
		return nil, "", err
	}
	return out.Items, out.NextPageToken, nil
}

func (c *circleAPIClient) ListOrganizationProjects(ctx context.Context, orgSlug, defaultVCS string) ([]string, error) {
	candidates := []string{orgSlug}
	if !strings.Contains(orgSlug, "/") {
		for _, vcsSlug := range vcsSlugCandidates(defaultVCS) {
			candidates = append(candidates, fmt.Sprintf("%s/%s", vcsSlug, orgSlug))
		}
	}
	candidates = uniqueStrings(candidates)

	var lastErr error
	for _, candidate := range candidates {
		var out []string
		var pageToken string

		for {
			q := url.Values{}
			if pageToken != "" {
				q.Set("page-token", pageToken)
			}

			var resp orgProjectListResponse
			if err := c.getJSON(ctx, fmt.Sprintf("organization/%s/project", candidate), q, &resp); err != nil {
				lastErr = err
				out = nil
				break
			}

			for _, item := range resp.Items {
				slug := strings.TrimSpace(item.Slug)
				if slug == "" {
					continue
				}
				if !strings.Contains(slug, "/") {
					continue
				}
				if len(strings.Split(slug, "/")) == 2 {
					slug = fmt.Sprintf("%s/%s", defaultVCS, slug)
				}
				out = append(out, slug)
			}

			if resp.NextPageToken == "" {
				break
			}
			pageToken = resp.NextPageToken
		}

		if len(out) > 0 {
			return out, nil
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("organization %q has no accessible projects", orgSlug)
}

func (c *circleAPIClient) ListAccessibleProjectsV1(ctx context.Context, defaultVCS, orgFilter string) ([]string, error) {
	requestURL, err := c.restClient.BaseURL.Parse("../v1.1/projects")
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Circle-Token", c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("v1 project discovery failed: %s", resp.Status)
	}

	var items []v1ProjectItem
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return nil, err
	}

	projects := make([]string, 0, len(items))
	normalizedFilter := strings.ToLower(strings.TrimSpace(orgFilter))
	for _, item := range items {
		log.Debug().
			Str("username", strings.TrimSpace(item.Username)).
			Str("reponame", strings.TrimSpace(item.Reponame)).
			Str("vcsType", strings.TrimSpace(item.VCSType)).
			Str("vcsURL", strings.TrimSpace(item.VCSURL)).
			Msg("Discovered project from CircleCI v1 API")

		if normalizedFilter != "" && strings.ToLower(strings.TrimSpace(item.Username)) != normalizedFilter {
			log.Debug().
				Str("username", strings.TrimSpace(item.Username)).
				Str("orgFilter", orgFilter).
				Msg("Skipped discovered project due to org filter mismatch")
			continue
		}

		slug, ok := projectSlugFromV1(item, defaultVCS)
		if !ok {
			log.Debug().
				Str("username", strings.TrimSpace(item.Username)).
				Str("reponame", strings.TrimSpace(item.Reponame)).
				Str("vcsType", strings.TrimSpace(item.VCSType)).
				Msg("Skipped discovered project because slug normalization failed")
			continue
		}

		log.Debug().
			Str("slug", slug).
			Msg("Normalized discovered project to scan slug")
		projects = append(projects, slug)
	}

	projects = uniqueStrings(projects)
	if len(projects) == 0 {
		return nil, fmt.Errorf("no accessible projects returned by v1 discovery")
	}

	return projects, nil
}

func (c *circleAPIClient) ListPipelineWorkflows(ctx context.Context, pipelineID string) ([]workflowItem, error) {
	var out workflowListResponse
	if err := c.getJSON(ctx, fmt.Sprintf("pipeline/%s/workflow", pipelineID), nil, &out); err != nil {
		return nil, err
	}
	return out.Items, nil
}

func (c *circleAPIClient) ListWorkflowJobs(ctx context.Context, workflowID string) ([]workflowJobItem, error) {
	var out workflowJobListResponse
	if err := c.getJSON(ctx, fmt.Sprintf("workflow/%s/job", workflowID), nil, &out); err != nil {
		return nil, err
	}
	return out.Items, nil
}

func (c *circleAPIClient) GetProjectJob(ctx context.Context, projectSlug string, jobNumber int) (projectJobResponse, error) {
	var out projectJobResponse
	err := c.getJSON(ctx, fmt.Sprintf("project/%s/job/%s", projectSlug, strconv.Itoa(jobNumber)), nil, &out)
	return out, err
}

func (c *circleAPIClient) GetProjectJobV1(ctx context.Context, projectSlug string, jobNumber int) (projectJobResponse, error) {
	requestURL, err := c.restClient.BaseURL.Parse(fmt.Sprintf("../v1.1/project/%s/%d", projectSlug, jobNumber))
	if err != nil {
		return projectJobResponse{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return projectJobResponse{}, err
	}
	req.Header.Set("Circle-Token", c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return projectJobResponse{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return projectJobResponse{}, fmt.Errorf("v1 job details failed: %s", resp.Status)
	}

	var out projectJobResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return projectJobResponse{}, err
	}

	return out, nil
}

func (c *circleAPIClient) ListJobArtifacts(ctx context.Context, projectSlug string, jobNumber int) ([]jobArtifactItem, error) {
	var out jobArtifactsResponse
	if err := c.getJSON(ctx, fmt.Sprintf("project/%s/%s/artifacts", projectSlug, strconv.Itoa(jobNumber)), nil, &out); err != nil {
		return nil, err
	}
	return out.Items, nil
}

func (c *circleAPIClient) ListJobTests(ctx context.Context, projectSlug string, jobNumber int) ([]jobTestItem, error) {
	var out jobTestsResponse
	if err := c.getJSON(ctx, fmt.Sprintf("project/%s/%s/tests", projectSlug, strconv.Itoa(jobNumber)), nil, &out); err != nil {
		return nil, err
	}
	return out.Items, nil
}

func (c *circleAPIClient) ListProjectInsightsWorkflows(ctx context.Context, projectSlug, branch string) ([]string, error) {
	q := url.Values{}
	if branch != "" {
		q.Set("branch", branch)
	}

	var resp struct {
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
	}
	if err := c.getJSON(ctx, fmt.Sprintf("insights/%s/workflows", projectSlug), q, &resp); err != nil {
		return nil, err
	}

	out := make([]string, 0, len(resp.Items))
	for _, item := range resp.Items {
		if strings.TrimSpace(item.Name) != "" {
			out = append(out, item.Name)
		}
	}

	return out, nil
}

func (c *circleAPIClient) GetProjectInsightsWorkflow(ctx context.Context, projectSlug, workflowName, branch string) (map[string]interface{}, error) {
	q := url.Values{}
	if branch != "" {
		q.Set("branch", branch)
	}

	var resp map[string]interface{}
	if err := c.getJSON(ctx, fmt.Sprintf("insights/%s/workflows/%s", projectSlug, url.PathEscape(workflowName)), q, &resp); err != nil {
		return nil, err
	}

	return resp, nil
}

func (c *circleAPIClient) DownloadWithAuth(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Circle-Token", c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("download failed: %s", resp.Status)
	}

	return io.ReadAll(resp.Body)
}

func (c *circleAPIClient) getJSON(ctx context.Context, path string, query url.Values, out interface{}) error {
	u := &url.URL{Path: path}
	if query != nil {
		u.RawQuery = query.Encode()
	}

	req, err := c.restClient.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req = req.WithContext(ctx)

	_, err = c.restClient.DoRequest(req, out)
	return err
}
