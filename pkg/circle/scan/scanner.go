package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/format"
	"github.com/CompassSecurity/pipeleek/pkg/logging"
	"github.com/CompassSecurity/pipeleek/pkg/scan/logline"
	"github.com/CompassSecurity/pipeleek/pkg/scan/result"
	"github.com/CompassSecurity/pipeleek/pkg/scan/runner"
	pkgscanner "github.com/CompassSecurity/pipeleek/pkg/scanner"
	"github.com/h2non/filetype"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type InitializeOptionsInput struct {
	Token                  string
	CircleURL              string
	Organization           string
	Projects               []string
	VCS                    string
	Branch                 string
	Statuses               []string
	WorkflowNames          []string
	JobNames               []string
	Since                  string
	Until                  string
	MaxPipelines           int
	IncludeTests           bool
	IncludeInsights        bool
	Artifacts              bool
	MaxArtifactSize        string
	ConfidenceFilter       []string
	MaxScanGoRoutines      int
	TruffleHogVerification bool
	HitTimeout             time.Duration
}

type ScanOptions struct {
	Token                  string
	CircleURL              string
	Organization           string
	Projects               []string
	Branch                 string
	Statuses               map[string]struct{}
	WorkflowNames          map[string]struct{}
	JobNames               map[string]struct{}
	Since                  *time.Time
	Until                  *time.Time
	MaxPipelines           int
	IncludeTests           bool
	IncludeInsights        bool
	Artifacts              bool
	MaxArtifactSize        int64
	ConfidenceFilter       []string
	MaxScanGoRoutines      int
	TruffleHogVerification bool
	HitTimeout             time.Duration
	Context                context.Context
	APIClient              CircleClient
	HTTPClient             *http.Client
}

type Scanner interface {
	pkgscanner.BaseScanner
	Status() *zerolog.Event
}

type circleScanner struct {
	options ScanOptions

	pipelinesScanned atomic.Int64
	jobsScanned      atomic.Int64
	artifactsScanned atomic.Int64
	currentProject   string
	mu               sync.RWMutex
}

var _ pkgscanner.BaseScanner = (*circleScanner)(nil)

func NewScanner(opts ScanOptions) Scanner {
	return &circleScanner{options: opts}
}

func (s *circleScanner) Status() *zerolog.Event {
	s.mu.RLock()
	project := s.currentProject
	s.mu.RUnlock()

	return log.Info().
		Int64("pipelinesScanned", s.pipelinesScanned.Load()).
		Int64("jobsScanned", s.jobsScanned.Load()).
		Int64("artifactsScanned", s.artifactsScanned.Load()).
		Str("currentProject", project)
}

func (s *circleScanner) Scan() error {
	runner.InitScanner(s.options.ConfidenceFilter)

	for _, project := range s.options.Projects {
		s.mu.Lock()
		s.currentProject = project
		s.mu.Unlock()

		log.Info().Str("project", project).Msg("Scanning CircleCI project")
		if err := s.scanProject(project); err != nil {
			log.Warn().Err(err).Str("project", project).Msg("Project scan failed, continuing")
		}
	}

	log.Info().Msg("Scan Finished, Bye Bye 🏳️‍🌈🔥")
	return nil
}

func (s *circleScanner) scanProject(project string) error {
	var pageToken string
	scanned := 0

	for {
		log.Debug().
			Str("project", project).
			Str("pageToken", pageToken).
			Int("pipelinesScannedForProject", scanned).
			Msg("Fetching pipeline page")

		pipelines, nextToken, err := s.options.APIClient.ListPipelines(s.options.Context, project, s.options.Branch, pageToken)
		if err != nil {
			return err
		}

		log.Debug().
			Str("project", project).
			Int("pipelinesReturned", len(pipelines)).
			Str("nextPageToken", nextToken).
			Msg("Fetched pipeline page")

		for _, pipeline := range pipelines {
			if s.options.MaxPipelines > 0 && scanned >= s.options.MaxPipelines {
				log.Debug().
					Str("project", project).
					Int("maxPipelines", s.options.MaxPipelines).
					Int("pipelinesScannedForProject", scanned).
					Msg("Reached max pipeline limit for project")
				return nil
			}

			if !s.inTimeWindow(parseRFC3339Ptr(pipeline.CreatedAt)) {
				continue
			}

			if !matchesFilter(s.options.Statuses, pipeline.State) {
				continue
			}

			s.pipelinesScanned.Add(1)
			scanned++

			log.Debug().
				Str("project", project).
				Str("pipelineID", pipeline.ID).
				Str("pipelineState", pipeline.State).
				Msg("Scanning pipeline")

			if err := s.scanPipeline(project, pipeline); err != nil {
				log.Warn().Err(err).Str("project", project).Str("pipeline", pipeline.ID).Msg("Pipeline scan failed, continuing")
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	if s.options.IncludeInsights {
		if err := s.scanProjectInsights(project); err != nil {
			log.Debug().Err(err).Str("project", project).Msg("Failed scanning project insights")
		}
	}

	return nil
}

func (s *circleScanner) scanProjectInsights(project string) error {
	log.Debug().Str("project", project).Msg("Scanning project insights")

	workflows, err := s.options.APIClient.ListProjectInsightsWorkflows(s.options.Context, project, s.options.Branch)
	if err != nil {
		return err
	}

	log.Debug().
		Str("project", project).
		Int("insightWorkflows", len(workflows)).
		Msg("Fetched project insights workflows")

	for _, workflowName := range workflows {
		if !matchesFilter(s.options.WorkflowNames, workflowName) {
			continue
		}

		details, err := s.options.APIClient.GetProjectInsightsWorkflow(s.options.Context, project, workflowName, s.options.Branch)
		if err != nil {
			continue
		}

		payload, err := json.Marshal(details)
		if err != nil {
			continue
		}

		findings, err := pkgscanner.DetectHits(payload, s.options.MaxScanGoRoutines, s.options.TruffleHogVerification, s.options.HitTimeout)
		if err != nil {
			continue
		}

		result.ReportFindings(findings, result.ReportOptions{
			LocationURL: strings.TrimRight(s.options.CircleURL, "/") + "/pipelines/" + project,
			JobName:     workflowName,
			BuildName:   "insights",
			Type:        logging.SecretTypeLog,
		})
	}

	return nil
}

func (s *circleScanner) scanPipeline(project string, pipeline pipelineItem) error {
	workflows, err := s.options.APIClient.ListPipelineWorkflows(s.options.Context, pipeline.ID)
	if err != nil {
		return err
	}

	log.Debug().
		Str("project", project).
		Str("pipelineID", pipeline.ID).
		Int("workflowsReturned", len(workflows)).
		Msg("Fetched pipeline workflows")

	for _, wf := range workflows {
		if !matchesFilter(s.options.WorkflowNames, wf.Name) {
			continue
		}
		if !matchesFilter(s.options.Statuses, wf.Status) {
			continue
		}
		if !s.inTimeWindow(parseRFC3339Ptr(wf.CreatedAt)) {
			continue
		}

		log.Debug().
			Str("project", project).
			Str("pipelineID", pipeline.ID).
			Str("workflowID", wf.ID).
			Str("workflowName", wf.Name).
			Str("workflowStatus", wf.Status).
			Msg("Scanning workflow")

		if err := s.scanWorkflow(project, pipeline, wf); err != nil {
			log.Warn().Err(err).Str("project", project).Str("workflow", wf.ID).Msg("Workflow scan failed, continuing")
		}
	}

	return nil
}

func (s *circleScanner) scanWorkflow(project string, pipeline pipelineItem, workflow workflowItem) error {
	jobs, err := s.options.APIClient.ListWorkflowJobs(s.options.Context, workflow.ID)
	if err != nil {
		return err
	}

	log.Debug().
		Str("project", project).
		Str("pipelineID", pipeline.ID).
		Str("workflowID", workflow.ID).
		Int("jobsReturned", len(jobs)).
		Msg("Fetched workflow jobs")

	for _, job := range jobs {
		if !matchesFilter(s.options.JobNames, job.Name) {
			continue
		}
		if !matchesFilter(s.options.Statuses, job.Status) {
			continue
		}

		log.Debug().
			Str("project", project).
			Str("workflowID", workflow.ID).
			Int("jobNumber", job.JobNumber).
			Str("jobName", job.Name).
			Str("jobStatus", job.Status).
			Msg("Scanning job")

		s.jobsScanned.Add(1)
		if err := s.scanJob(project, pipeline, workflow, job); err != nil {
			log.Warn().Err(err).Str("project", project).Int("jobNumber", job.JobNumber).Msg("Job scan failed, continuing")
		}
	}

	return nil
}

func (s *circleScanner) scanJob(project string, pipeline pipelineItem, workflow workflowItem, job workflowJobItem) error {
	jobDetails, err := s.options.APIClient.GetProjectJob(s.options.Context, project, job.JobNumber)
	if err != nil {
		return err
	}
	if len(jobDetails.Steps) == 0 {
		legacyDetails, legacyErr := s.options.APIClient.GetProjectJobV1(s.options.Context, project, job.JobNumber)
		if legacyErr == nil && len(legacyDetails.Steps) > 0 {
			if strings.TrimSpace(jobDetails.Name) == "" {
				jobDetails.Name = legacyDetails.Name
			}
			if strings.TrimSpace(jobDetails.WebURL) == "" {
				jobDetails.WebURL = legacyDetails.WebURL
			}
			jobDetails.Steps = legacyDetails.Steps
		}
	}

	log.Debug().
		Str("project", project).
		Int("pipelineNumber", pipeline.Number).
		Str("workflowID", workflow.ID).
		Int("jobNumber", job.JobNumber).
		Int("steps", len(jobDetails.Steps)).
		Msg("Fetched job details")

	locationURL := circleAppWorkflowURL(workflow.ID)
	jobURL := circleAppJobURL(project, pipeline.Number, workflow.ID, job.JobNumber, locationURL)

	if err := s.scanJobLogs(project, workflow, jobURL, jobDetails); err != nil {
		log.Debug().Err(err).Str("project", project).Int("job", job.JobNumber).Msg("Failed scanning job logs")
	}

	if s.options.IncludeTests {
		if err := s.scanJobTests(project, workflow, job, jobDetails, jobURL); err != nil {
			log.Debug().Err(err).Str("project", project).Int("job", job.JobNumber).Msg("Failed scanning job tests")
		}
	}

	if s.options.Artifacts {
		if err := s.scanJobArtifacts(project, workflow, job, jobDetails, jobURL); err != nil {
			log.Debug().Err(err).Str("project", project).Int("job", job.JobNumber).Msg("Failed scanning job artifacts")
		}
	}

	return nil
}

func (s *circleScanner) scanJobLogs(project string, workflow workflowItem, jobURL string, details projectJobResponse) error {
	log.Debug().
		Str("project", project).
		Str("workflowID", workflow.ID).
		Str("jobName", details.Name).
		Int("steps", len(details.Steps)).
		Msg("Scanning job logs")

	for _, step := range details.Steps {
		for _, action := range step.Actions {
			if action.OutputURL == "" {
				continue
			}

			logBytes, err := s.options.APIClient.DownloadWithAuth(s.options.Context, action.OutputURL)
			if err != nil {
				continue
			}
			if len(logBytes) == 0 {
				continue
			}

			processed := flattenLogOutput(logBytes)
			logResult, err := logline.ProcessLogs(processed, logline.ProcessOptions{
				MaxGoRoutines:     s.options.MaxScanGoRoutines,
				VerifyCredentials: s.options.TruffleHogVerification,
				HitTimeout:        s.options.HitTimeout,
			})
			if err != nil {
				continue
			}

			if len(logResult.Findings) > 0 {
				log.Debug().
					Str("project", project).
					Str("workflowID", workflow.ID).
					Str("jobName", details.Name).
					Str("stepName", step.Name).
					Int("findings", len(logResult.Findings)).
					Msg("Detected findings in job log output")
			}

			stepLabel := step.Name
			if action.Name != "" && action.Name != step.Name {
				stepLabel = step.Name + " / " + action.Name
			}
			result.ReportFindings(logResult.Findings, result.ReportOptions{
				LocationURL: jobURL,
				JobName:     workflow.Name,
				BuildName:   details.Name + " / " + stepLabel,
				Type:        logging.SecretTypeLog,
			})
		}
	}

	return nil
}

func (s *circleScanner) scanJobTests(project string, workflow workflowItem, job workflowJobItem, details projectJobResponse, locationURL string) error {
	tests, err := s.options.APIClient.ListJobTests(s.options.Context, project, job.JobNumber)
	if err != nil {
		return err
	}

	log.Debug().
		Str("project", project).
		Str("workflowID", workflow.ID).
		Int("jobNumber", job.JobNumber).
		Int("testsReturned", len(tests)).
		Msg("Fetched job tests")

	if len(tests) == 0 {
		return nil
	}

	payload, err := json.Marshal(tests)
	if err != nil {
		return err
	}

	findings, err := pkgscanner.DetectHits(payload, s.options.MaxScanGoRoutines, s.options.TruffleHogVerification, s.options.HitTimeout)
	if err != nil {
		return err
	}

	if len(findings) > 0 {
		log.Debug().
			Str("project", project).
			Str("workflowID", workflow.ID).
			Int("jobNumber", job.JobNumber).
			Int("findings", len(findings)).
			Msg("Detected findings in job tests")
	}

	result.ReportFindings(findings, result.ReportOptions{
		LocationURL: locationURL,
		JobName:     workflow.Name,
		BuildName:   fmt.Sprintf("%s tests", details.Name),
		Type:        logging.SecretTypeLog,
	})

	return nil
}

func (s *circleScanner) scanJobArtifacts(project string, workflow workflowItem, job workflowJobItem, details projectJobResponse, locationURL string) error {
	artifacts, err := s.options.APIClient.ListJobArtifacts(s.options.Context, project, job.JobNumber)
	if err != nil {
		return err
	}

	log.Debug().
		Str("project", project).
		Str("workflowID", workflow.ID).
		Int("jobNumber", job.JobNumber).
		Int("artifactsReturned", len(artifacts)).
		Msg("Fetched job artifacts")

	for _, artifact := range artifacts {
		if artifact.URL == "" || artifact.Path == "" {
			continue
		}

		content, err := s.options.APIClient.DownloadWithAuth(s.options.Context, artifact.URL)
		if err != nil {
			continue
		}

		if int64(len(content)) > s.options.MaxArtifactSize {
			log.Debug().
				Str("project", project).
				Str("workflowID", workflow.ID).
				Int("jobNumber", job.JobNumber).
				Str("artifact", artifact.Path).
				Int("bytes", len(content)).
				Int64("maxBytes", s.options.MaxArtifactSize).
				Msg("Skipped large artifact")
			continue
		}

		s.artifactsScanned.Add(1)
		if filetype.IsArchive(content) {
			pkgscanner.HandleArchiveArtifact(artifact.Path, content, locationURL, details.Name, s.options.TruffleHogVerification, s.options.HitTimeout)
			continue
		}

		pkgscanner.DetectFileHits(content, locationURL, details.Name, artifact.Path, workflow.Name, s.options.TruffleHogVerification, s.options.HitTimeout)
	}

	return nil
}

func (s *circleScanner) inTimeWindow(value *time.Time) bool {
	if value == nil {
		return true
	}
	if s.options.Since != nil && value.Before(*s.options.Since) {
		return false
	}
	if s.options.Until != nil && value.After(*s.options.Until) {
		return false
	}
	return true
}

func InitializeOptions(input InitializeOptionsInput) (ScanOptions, error) {
	orgName := normalizedOrgName(input.Organization)

	if input.CircleURL == "" {
		input.CircleURL = "https://circleci.com"
	}
	if input.VCS == "" {
		input.VCS = "github"
	}

	maxArtifactBytes, err := format.ParseHumanSize(input.MaxArtifactSize)
	if err != nil {
		return ScanOptions{}, err
	}

	since, err := parseOptionalRFC3339(input.Since)
	if err != nil {
		return ScanOptions{}, fmt.Errorf("invalid --since value: %w", err)
	}
	until, err := parseOptionalRFC3339(input.Until)
	if err != nil {
		return ScanOptions{}, fmt.Errorf("invalid --until value: %w", err)
	}
	if since != nil && until != nil && since.After(*until) {
		return ScanOptions{}, fmt.Errorf("--since must be before --until")
	}

	projects := make([]string, 0, len(input.Projects))
	for _, p := range input.Projects {
		normalized, err := normalizeProjectSlug(p, input.VCS)
		if err != nil {
			return ScanOptions{}, err
		}
		if orgName != "" && !belongsToOrg(normalized, orgName) {
			continue
		}
		projects = append(projects, normalized)
	}

	baseURL, err := url.Parse(strings.TrimRight(input.CircleURL, "/") + "/api/v2/")
	if err != nil {
		return ScanOptions{}, err
	}

	httpClient := &http.Client{Timeout: 45 * time.Second}
	apiClient := newCircleAPIClient(baseURL, input.Token, httpClient)

	if len(projects) == 0 {
		if strings.TrimSpace(input.Organization) != "" {
			resolved, err := apiClient.ListOrganizationProjects(context.Background(), input.Organization, input.VCS)
			if err != nil {
				// v1 fallback only makes sense for GitHub/Bitbucket orgs whose username
				// matches the GitHub/Bitbucket username in v1 project records. For native
				// circleci/ orgs, the orgName is a UUID-like slug that will never match a
				// VCS username, so skip the v1 fallback and surface the original error.
				v1Filter := orgName
				if strings.HasPrefix(strings.ToLower(input.Organization), "circleci/") {
					v1Filter = ""
				}
				fallbackProjects, fallbackErr := apiClient.ListAccessibleProjectsV1(context.Background(), input.VCS, v1Filter)
				if fallbackErr != nil {
					return ScanOptions{}, fmt.Errorf("ListOrganizationProjects failed: %v; fallback ListAccessibleProjectsV1 failed: %w", err, fallbackErr)
				}
				projects = uniqueStrings(append(projects, fallbackProjects...))
			} else {
				projects = resolved
			}
		} else {
			resolved, err := apiClient.ListAccessibleProjectsV1(context.Background(), input.VCS, "")
			if err != nil {
				return ScanOptions{}, fmt.Errorf("provide --project or --org, or ensure token can list accessible projects: %w", err)
			}
			projects = resolved
		}
	}

	if len(projects) == 0 {
		return ScanOptions{}, fmt.Errorf("no project remains after applying organization filter")
	}

	return ScanOptions{
		Token:                  input.Token,
		CircleURL:              input.CircleURL,
		Organization:           input.Organization,
		Projects:               projects,
		Branch:                 input.Branch,
		Statuses:               toFilterSet(input.Statuses),
		WorkflowNames:          toFilterSet(input.WorkflowNames),
		JobNames:               toFilterSet(input.JobNames),
		Since:                  since,
		Until:                  until,
		MaxPipelines:           input.MaxPipelines,
		IncludeTests:           input.IncludeTests,
		IncludeInsights:        input.IncludeInsights,
		Artifacts:              input.Artifacts,
		MaxArtifactSize:        maxArtifactBytes,
		ConfidenceFilter:       input.ConfidenceFilter,
		MaxScanGoRoutines:      input.MaxScanGoRoutines,
		TruffleHogVerification: input.TruffleHogVerification,
		HitTimeout:             input.HitTimeout,
		Context:                context.Background(),
		APIClient:              apiClient,
		HTTPClient:             httpClient,
	}, nil
}

func parseOptionalRFC3339(value string) (*time.Time, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func parseRFC3339Ptr(value string) *time.Time {
	if value == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil
	}
	return &t
}

func flattenLogOutput(raw []byte) []byte {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return raw
	}

	if strings.HasPrefix(trimmed, "[") {
		var entries []map[string]interface{}
		if err := json.Unmarshal([]byte(trimmed), &entries); err == nil && len(entries) > 0 {
			var b strings.Builder
			for _, entry := range entries {
				if msg, ok := entry["message"].(string); ok && msg != "" {
					b.WriteString(msg)
					b.WriteByte('\n')
				}
			}
			if b.Len() > 0 {
				return []byte(b.String())
			}
		}
	}

	if strings.HasPrefix(trimmed, "{") {
		var entry map[string]interface{}
		if err := json.Unmarshal([]byte(trimmed), &entry); err == nil {
			if msg, ok := entry["message"].(string); ok && msg != "" {
				return []byte(msg)
			}
		}
	}

	return []byte(trimmed)
}

func circleAppWorkflowURL(workflowID string) string {
	if strings.TrimSpace(workflowID) == "" {
		return "https://app.circleci.com/pipelines"
	}
	return fmt.Sprintf("https://app.circleci.com/pipelines/workflows/%s", workflowID)
}

// circleAppJobURL builds the stable CircleCI app job URL.
// Format: https://app.circleci.com/pipelines/<vcs>/<org>/<repo>/<pipeline-number>/workflows/<workflow-id>/jobs/<job-number>
func circleAppJobURL(project string, pipelineNumber int, workflowID string, jobNum int, fallback string) string {
	parts := strings.Split(project, "/")
	if len(parts) != 3 || strings.TrimSpace(workflowID) == "" || pipelineNumber <= 0 || jobNum <= 0 {
		return fallback
	}

	vcs := normalizeVCSName(parts[0])
	return fmt.Sprintf(
		"https://app.circleci.com/pipelines/%s/%s/%s/%d/workflows/%s/jobs/%d",
		vcs,
		parts[1],
		parts[2],
		pipelineNumber,
		workflowID,
		jobNum,
	)
}
