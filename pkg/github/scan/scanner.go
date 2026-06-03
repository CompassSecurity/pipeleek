package scan

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/format"
	"github.com/CompassSecurity/pipeleek/pkg/httpclient"
	artifactproc "github.com/CompassSecurity/pipeleek/pkg/scan/artifact"
	"github.com/CompassSecurity/pipeleek/pkg/scan/logline"
	"github.com/CompassSecurity/pipeleek/pkg/scan/result"
	"github.com/CompassSecurity/pipeleek/pkg/scan/runner"
	pkgscanner "github.com/CompassSecurity/pipeleek/pkg/scanner"
	"github.com/gofri/go-github-ratelimit/v2/github_ratelimit"
	"github.com/gofri/go-github-ratelimit/v2/github_ratelimit/github_primary_ratelimit"
	"github.com/gofri/go-github-ratelimit/v2/github_ratelimit/github_secondary_ratelimit"
	"github.com/google/go-github/v69/github"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"resty.dev/v3"
)

// ScanOptions contains configuration options for GitHub scanning operations.
type ScanOptions struct {
	AccessToken            string
	ConfidenceFilter       []string
	MaxScanGoRoutines      int
	TruffleHogVerification bool
	MaxWorkflows           int
	Organization           string
	Owned                  bool
	User                   string
	Public                 bool
	SearchQuery            string
	Artifacts              bool
	GitHubURL              string
	Repo                   string
	MaxArtifactSize        int64
	HitTimeout             time.Duration
	Context                context.Context
	Client                 *github.Client
	HttpClient             *resty.Client
}

type Scanner interface {
	pkgscanner.BaseScanner
	GetRateLimitStatus() *zerolog.Event
}

type scanner struct {
	options ScanOptions
}

var _ pkgscanner.BaseScanner = (*scanner)(nil)

func NewScanner(opts ScanOptions) Scanner {
	return &scanner{
		options: opts,
	}
}

// SetupClient creates and configures a GitHub API client with rate limiting support.
func SetupClient(accessToken string, baseURL string) *github.Client {
	if baseURL == "" {
		baseURL = "https://api.github.com/"
	}
	rateLimiter := github_ratelimit.New(httpclient.GetPipeleekTransport(),
		github_primary_ratelimit.WithLimitDetectedCallback(func(ctx *github_primary_ratelimit.CallbackContext) {
			resetTime := ctx.ResetTime.Add(time.Duration(time.Second * 30))
			log.Info().Str("category", string(ctx.Category)).Time("reset", resetTime).Msg("Primary rate limit detected, will resume automatically")
			time.Sleep(time.Until(resetTime))
			log.Info().Str("category", string(ctx.Category)).Msg("Resuming")
		}),
		github_secondary_ratelimit.WithLimitDetectedCallback(func(ctx *github_secondary_ratelimit.CallbackContext) {
			resetTime := ctx.ResetTime.Add(time.Duration(time.Second * 30))
			log.Info().Time("reset", *ctx.ResetTime).Dur("totalSleep", *ctx.TotalSleepTime).Msg("Secondary rate limit detected, will resume automatically")
			time.Sleep(time.Until(resetTime))
			log.Info().Msg("Resuming")
		}),
	)

	client := github.NewClient(&http.Client{Transport: rateLimiter}).WithAuthToken(accessToken)
	if baseURL != "https://api.github.com/" {
		client, _ = client.WithEnterpriseURLs(baseURL, baseURL)
	}
	return client
}

// Scan performs the GitHub scanning operation based on the configured options.
func (s *scanner) Scan() error {
	runner.InitScanner(s.options.ConfidenceFilter)

	if s.options.Repo != "" {
		log.Info().Str("repository", s.options.Repo).Msg("Scanning single repository")
		s.scanSingleRepository(s.options.Repo)
	} else if s.options.Owned {
		log.Info().Msg("Scanning authenticated user's owned repositories actions")
		s.scanRepositories()
	} else if s.options.User != "" {
		log.Info().Str("users", s.options.User).Msg("Scanning user's repositories actions")
		s.scanRepositories()
	} else if s.options.SearchQuery != "" {
		log.Info().Str("query", s.options.SearchQuery).Msg("Searching repositories")
		s.searchRepositories(s.options.SearchQuery)
	} else if s.options.Public {
		log.Info().Msg("Scanning most recent public repositories")
		id := s.identifyNewestPublicProjectId()
		s.scanAllPublicRepositories(id)
	} else {
		log.Info().Str("organization", s.options.Organization).Msg("Scanning organization repositories actions")
		s.scanRepositories()
	}

	log.Info().Msg("Scan Finished, Bye Bye 🏳️‍🌈🔥")
	return nil
}

// GetRateLimitStatus returns the current rate limit status for the GitHub API.
func (s *scanner) GetRateLimitStatus() *zerolog.Event {
	rateLimit, resp, err := s.options.Client.RateLimit.Get(s.options.Context)
	if resp == nil {
		return log.Info().Str("rateLimit", "You're rate limited, just wait ✨")
	}

	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Failed fetching rate limit stats")
	}

	return log.Info().Int("coreRateLimitRemaining", rateLimit.Core.Remaining).Time("coreRateLimitReset", rateLimit.Core.Reset.Time).Int("searchRateLimitRemaining", rateLimit.Search.Remaining).Time("searchRateLimitReset", rateLimit.Search.Reset.Time)
}

func (s *scanner) searchRepositories(query string) {
	searchOpt := github.SearchOptions{}
	for {
		searchResults, resp, err := s.options.Client.Search.Repositories(s.options.Context, query, &searchOpt)
		if err != nil {
			log.Fatal().Stack().Err(err).Msg("Failed searching repositories")
		}

		for _, repo := range searchResults.Repositories {
			log.Debug().Str("name", *repo.Name).Str("url", *repo.HTMLURL).Msg("Scan")
			s.iterateWorkflowRuns(repo)
		}

		if resp.NextPage == 0 {
			break
		}
		searchOpt.Page = resp.NextPage
	}
}

func (s *scanner) scanAllPublicRepositories(latestProjectId int64) {
	opt := &github.RepositoryListAllOptions{
		Since: latestProjectId,
	}

	// iterating through the repos in reverse must take into account, that missing ids prevent easy pagination as they create holes in the list.
	// thus we keep a temporary cache of the ids of the last 5 pages and check if we alredy scanned the repo id, or skip them.
	tmpIdCache := make(map[int64]struct{})
	pageCounter := 0
	for opt.Since >= 0 {
		if pageCounter > 4 {
			pageCounter = 0
			tmpIdCache = deleteHighestXKeys(tmpIdCache, 100)
		}

		repos, _, err := s.options.Client.Repositories.ListAll(s.options.Context, opt)
		if err != nil {
			log.Fatal().Stack().Err(err).Msg("Failed fetching authenticated user repos")
		}

		sort.SliceStable(repos, func(i, j int) bool {
			return *repos[i].ID > *repos[j].ID
		})

		for _, repo := range repos {
			_, ok := tmpIdCache[*repo.ID]
			if ok {
				continue
			} else {
				tmpIdCache[*repo.ID] = struct{}{}
			}

			log.Debug().Str("url", *repo.HTMLURL).Msg("Scan")
			s.iterateWorkflowRuns(repo)
			opt.Since = *repo.ID
		}

		// 100 = page size, ideally no ids miss thus we cannot go higher
		opt.Since = opt.Since - 100
		pageCounter = pageCounter + 1
	}
}

func deleteHighestXKeys(m map[int64]struct{}, nrKeys int) map[int64]struct{} {
	if len(m) < nrKeys {
		return make(map[int64]struct{})
	}

	keys := make([]int64, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	sort.Slice(keys, func(i, j int) bool {
		return keys[i] > keys[j]
	})

	for i := 0; i < nrKeys; i++ {
		delete(m, keys[i])
	}
	return m
}

// DeleteHighestXKeys removes the highest nrKeys keys from the map.
func DeleteHighestXKeys(m map[int64]struct{}, nrKeys int) map[int64]struct{} {
	return deleteHighestXKeys(m, nrKeys)
}

func (s *scanner) scanRepositories() {
	if s.options.Organization != "" {
		s.scanOrgRepositories(s.options.Organization)
	} else if s.options.User != "" {
		s.scanUserRepositories(s.options.User)
	} else {
		s.scanAuthenticatedUserRepositories(s.options.Owned)
	}
}

func validateRepoFormat(repo string) (owner, name string, valid bool) {
	parts := strings.Split(repo, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// ValidateRepoFormat validates the format of a repository string.
// Returns owner, name and whether the format is valid.
func ValidateRepoFormat(repo string) (owner, name string, valid bool) {
	return validateRepoFormat(repo)
}

func (s *scanner) scanSingleRepository(repoFullName string) {
	owner, name, valid := validateRepoFormat(repoFullName)
	if !valid {
		log.Fatal().Str("repo", repoFullName).Msg("Invalid repository format. Expected: owner/repo")
	}

	repo, resp, err := s.options.Client.Repositories.Get(s.options.Context, owner, name)
	if resp != nil && resp.StatusCode == 404 {
		log.Fatal().Str("repo", repoFullName).Msg("Repository not found")
	}
	if err != nil {
		log.Fatal().Stack().Err(err).Str("repo", repoFullName).Msg("Failed fetching repository")
	}

	log.Debug().Str("name", *repo.Name).Str("url", *repo.HTMLURL).Msg("Scan")
	s.iterateWorkflowRuns(repo)
}

func (s *scanner) scanOrgRepositories(organization string) {
	opt := &github.RepositoryListByOrgOptions{
		Sort:        "updated",
		ListOptions: github.ListOptions{PerPage: 100},
	}
	for {
		repos, resp, err := s.options.Client.Repositories.ListByOrg(s.options.Context, organization, opt)
		if err != nil {
			log.Fatal().Stack().Err(err).Msg("Failed fetching organization repos")
		}
		for _, repo := range repos {
			log.Debug().Str("name", *repo.Name).Str("url", *repo.HTMLURL).Msg("Scan")
			s.iterateWorkflowRuns(repo)
		}
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
}

func (s *scanner) scanUserRepositories(user string) {
	opt := &github.RepositoryListByUserOptions{
		Sort:        "updated",
		ListOptions: github.ListOptions{PerPage: 100},
	}
	for {
		repos, resp, err := s.options.Client.Repositories.ListByUser(s.options.Context, user, opt)
		if err != nil {
			log.Fatal().Stack().Err(err).Msg("Failed fetching user repos")
		}
		for _, repo := range repos {
			log.Debug().Str("name", *repo.Name).Str("url", *repo.HTMLURL).Msg("Scan")
			s.iterateWorkflowRuns(repo)
		}
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
}

func (s *scanner) scanAuthenticatedUserRepositories(owned bool) {
	affiliation := "owner,collaborator,organization_member"
	if owned {
		affiliation = "owner"
	}
	opt := &github.RepositoryListByAuthenticatedUserOptions{
		ListOptions: github.ListOptions{PerPage: 100},
		Affiliation: affiliation,
	}
	for {
		repos, resp, err := s.options.Client.Repositories.ListByAuthenticatedUser(s.options.Context, opt)
		if err != nil {
			log.Fatal().Stack().Err(err).Msg("Failed fetching authenticated user repos")
		}
		for _, repo := range repos {
			log.Debug().Str("name", *repo.Name).Str("url", *repo.HTMLURL).Msg("Scan")
			s.iterateWorkflowRuns(repo)
		}
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
}

func (s *scanner) iterateWorkflowRuns(repo *github.Repository) {
	opt := github.ListWorkflowRunsOptions{
		ListOptions: github.ListOptions{PerPage: 100},
	}
	wfCount := 0
	for {
		workflowRuns, resp, err := s.options.Client.Actions.ListRepositoryWorkflowRuns(s.options.Context, *repo.Owner.Login, *repo.Name, &opt)

		if resp == nil {
			log.Trace().Msg("Empty response due to rate limit, resume now<")
			continue
		}

		if resp.StatusCode == 404 {
			return
		}

		if err != nil {
			log.Error().Stack().Err(err).Msg("Failed fetching workflow runs")
			return
		}

		for _, workflowRun := range workflowRuns.WorkflowRuns {
			log.Debug().Str("name", *workflowRun.DisplayTitle).Str("url", *workflowRun.HTMLURL).Msg("Workflow run")
			s.downloadWorkflowRunLog(repo, workflowRun)

			if s.options.Artifacts {
				s.listArtifacts(workflowRun)
			}

			wfCount = wfCount + 1
			if wfCount >= s.options.MaxWorkflows && s.options.MaxWorkflows > 0 {
				log.Debug().Str("name", *workflowRun.DisplayTitle).Str("url", *workflowRun.HTMLURL).Msg("Reached MaxWorkflow runs, skip remaining")
				return
			}
		}

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
}

func (s *scanner) downloadWorkflowRunLog(repo *github.Repository, workflowRun *github.WorkflowRun) {
	logURL, resp, err := s.options.Client.Actions.GetWorkflowRunLogs(s.options.Context, *repo.Owner.Login, *repo.Name, *workflowRun.ID, 5)

	if resp == nil {
		log.Trace().Msg("downloadWorkflowRunLog Empty response")
		return
	}

	// already deleted, skip
	switch resp.StatusCode {
	case 410:
		log.Debug().Str("workflowRunName", *workflowRun.Name).Msg("Skipped expired")
		return
	case 404:
		return
	}

	if err != nil {
		log.Error().Stack().Err(err).Msg("Failed getting workflow run log URL")
		return
	}

	log.Trace().Msg("Downloading run log")
	logs := s.downloadRunLogZIP(logURL.String())
	log.Trace().Msg("Finished downloading run log")

	logResult, err := logline.ProcessLogs(logs, logline.ProcessOptions{
		MaxGoRoutines:     s.options.MaxScanGoRoutines,
		VerifyCredentials: s.options.TruffleHogVerification,
		BuildURL:          *workflowRun.HTMLURL,
		HitTimeout:        s.options.HitTimeout,
	})
	if err != nil {
		log.Debug().Err(err).Str("workflowRun", *workflowRun.HTMLURL).Msg("Failed detecting secrets")
		return
	}

	result.ReportFindings(logResult.Findings, result.ReportOptions{
		LocationURL: *workflowRun.HTMLURL,
	})
	log.Trace().Msg("Finished scannig run log")
}

func (s *scanner) downloadRunLogZIP(url string) []byte {
	res, err := s.options.HttpClient.R().Get(url)
	logLines := make([]byte, 0)

	if err != nil {
		return logLines
	}

	if res.StatusCode() == 200 {
		body := res.Bytes()

		zipResult, err := logline.ExtractLogsFromZip(body)
		if err != nil {
			log.Err(err).Msg("Failed extracting logs from zip")
			return logLines
		}

		return zipResult.ExtractedLogs
	}

	return logLines
}

func (s *scanner) identifyNewestPublicProjectId() int64 {
	for {
		listOpts := github.ListOptions{PerPage: 1000}
		events, resp, err := s.options.Client.Activity.ListEvents(s.options.Context, &listOpts)
		if err != nil {
			log.Fatal().Stack().Err(err).Msg("Failed fetching activity")
		}
		for _, event := range events {
			eventType := *event.Type
			log.Trace().Str("type", eventType).Msg("Event")
			if eventType == "CreateEvent" {
				repo, _, err := s.options.Client.Repositories.GetByID(s.options.Context, *event.Repo.ID)
				if err != nil {
					log.Fatal().Stack().Err(err).Msg("Failed fetching Web URL of latest repo")
				}
				log.Info().Int64("Id", *repo.ID).Str("url", *repo.HTMLURL).Msg("Identified latest public repository")
				return *event.Repo.ID
			}
		}

		if resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}

	log.Fatal().Msg("Failed finding a CreateEvent and thus no rerpository id")
	return -1
}

func (s *scanner) listArtifacts(workflowRun *github.WorkflowRun) {
	listOpt := github.ListOptions{PerPage: 100}
	for {
		artifactList, resp, err := s.options.Client.Actions.ListWorkflowRunArtifacts(s.options.Context, *workflowRun.Repository.Owner.Login, *workflowRun.Repository.Name, *workflowRun.ID, &listOpt)
		if resp == nil {
			return
		}

		if resp.StatusCode == 404 {
			return
		}

		if err != nil {
			log.Error().Stack().Err(err).Msg("Failed fetching artifacts list")
			return
		}

		for _, artifact := range artifactList.Artifacts {
			log.Debug().Str("name", *artifact.Name).Str("url", *artifact.ArchiveDownloadURL).Msg("Scan")
			s.analyzeArtifact(workflowRun, artifact)
		}

		if resp.NextPage == 0 {
			break
		}
		listOpt.Page = resp.NextPage
	}
}

func (s *scanner) analyzeArtifact(workflowRun *github.WorkflowRun, artifact *github.Artifact) {
	if artifact.SizeInBytes != nil && *artifact.SizeInBytes > s.options.MaxArtifactSize {
		log.Debug().
			Int64("bytes", *artifact.SizeInBytes).
			Int64("maxBytes", s.options.MaxArtifactSize).
			Str("name", *artifact.Name).
			Str("url", *workflowRun.HTMLURL).
			Msg("Skipped large artifact")
		return
	}

	url, resp, err := s.options.Client.Actions.DownloadArtifact(s.options.Context, *workflowRun.Repository.Owner.Login, *workflowRun.Repository.Name, *artifact.ID, 5)

	if resp == nil {
		log.Trace().Msg("analyzeArtifact Empty response")
		return
	}

	// already deleted, skip
	if resp.StatusCode == 410 {
		log.Debug().Str("workflowRunName", *workflowRun.Name).Msg("Skipped expired artifact")
		return
	}

	if err != nil {
		log.Err(err).Msg("Failed getting artifact download URL")
		return
	}

	res, err := s.options.HttpClient.R().Get(url.String())

	if err != nil {
		log.Err(err).Str("workflow", url.String()).Msg("Failed downloading artifacts zip")
		return
	}

	if res.StatusCode() == 200 {
		body := res.Bytes()

		_, err = artifactproc.ProcessZipArtifact(body, artifactproc.ProcessOptions{
			MaxGoRoutines:     s.options.MaxScanGoRoutines,
			VerifyCredentials: s.options.TruffleHogVerification,
			BuildURL:          *workflowRun.HTMLURL,
			ArtifactName:      *workflowRun.Name,
			HitTimeout:        s.options.HitTimeout,
		})
		if err != nil {
			log.Err(err).Str("url", url.String()).Msg("Failed processing artifact zip")
			return
		}
	}
}

// InitializeOptions prepares scan options from CLI parameters.
func InitializeOptions(accessToken, gitHubURL, repo, organization, user, searchQuery, maxArtifactSizeStr string,
	owned, public, artifacts, truffleHogVerification bool,
	maxWorkflows, maxScanGoRoutines int, confidenceFilter []string, hitTimeout time.Duration) (ScanOptions, error) {

	byteSize, err := format.ParseHumanSize(maxArtifactSizeStr)
	if err != nil {
		return ScanOptions{}, err
	}

	ctx := context.WithValue(context.Background(), github.BypassRateLimitCheck, true)
	client := SetupClient(accessToken, gitHubURL)
	httpClient := httpclient.GetPipeleekHTTPClient("", nil, nil)

	return ScanOptions{
		AccessToken:            accessToken,
		ConfidenceFilter:       confidenceFilter,
		MaxScanGoRoutines:      maxScanGoRoutines,
		TruffleHogVerification: truffleHogVerification,
		MaxWorkflows:           maxWorkflows,
		Organization:           organization,
		Owned:                  owned,
		User:                   user,
		Public:                 public,
		SearchQuery:            searchQuery,
		Artifacts:              artifacts,
		GitHubURL:              gitHubURL,
		Repo:                   repo,
		MaxArtifactSize:        byteSize,
		HitTimeout:             hitTimeout,
		Context:                ctx,
		Client:                 client,
		HttpClient:             httpClient,
	}, nil
}
