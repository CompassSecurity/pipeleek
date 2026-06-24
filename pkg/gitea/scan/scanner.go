package gitea

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"code.gitea.io/sdk/gitea"
	"github.com/CompassSecurity/pipeleek/pkg/format"
	"github.com/CompassSecurity/pipeleek/pkg/httpclient"
	"github.com/CompassSecurity/pipeleek/pkg/scan/runner"
	pkgscanner "github.com/CompassSecurity/pipeleek/pkg/scanner"
	"github.com/rs/zerolog/log"
	"resty.dev/v3"
)

// ScanOptions is an alias for GiteaScanOptions for interface consistency with other providers.
type ScanOptions = GiteaScanOptions

var scanOptions GiteaScanOptions

type Scanner interface {
	pkgscanner.BaseScanner
}

type giteaScanner struct {
	options ScanOptions
}

var _ pkgscanner.BaseScanner = (*giteaScanner)(nil)

func NewScanner(opts ScanOptions) Scanner {
	return &giteaScanner{
		options: opts,
	}
}

// Scan performs the Gitea scanning operation.
func (s *giteaScanner) Scan() error {
	// Set the global scanOptions for compatibility with existing helper functions
	scanOptions = s.options

	runner.InitScanner(s.options.ConfidenceFilter)
	if !s.options.TruffleHogVerification {
		log.Info().Msg("TruffleHog verification is disabled")
	}

	s.scanRepositories()
	log.Info().Msg("Scan Finished, Bye Bye 🏳️‍🌈🔥")
	return nil
}

func (s *giteaScanner) scanRepositories() {
	if s.options.Repository != "" {
		log.Info().Str("repository", s.options.Repository).Msg("Scan")
		s.scanSingleRepository(s.options.Repository)
	} else if s.options.Organization != "" {
		log.Info().Str("organization", s.options.Organization).Msg("Scan organization")
		s.scanOrganizationRepositories(s.options.Organization)
	} else if s.options.Owned {
		log.Info().Msg("Scan user owned")
		s.scanOwnedRepositories()
	} else {
		log.Info().Msg("Scan all")
		s.scanAllRepositories()
	}
}

func (s *giteaScanner) scanSingleRepository(repoFullName string) {
	parts := strings.Split(repoFullName, "/")
	if len(parts) != 2 {
		log.Error().Str("repository", repoFullName).Msg("Invalid repository format, expected owner/repo")
		return
	}

	owner := parts[0]
	repoName := parts[1]

	repo, _, err := s.options.Client.GetRepo(owner, repoName)
	if err != nil {
		log.Error().Err(err).Str("repository", repoFullName).Msg("failed to get repository")
		return
	}

	if repo == nil {
		log.Error().Str("repository", repoFullName).Msg("repository not found (nil response)")
		return
	}

	log.Info().Str("url", repo.HTMLURL).Msg("Scanning repository")
	s.scanRepository(repo)
}

func (s *giteaScanner) scanAllRepositories() {
	opt := gitea.SearchRepoOptions{
		Sort:  "updated",
		Order: "desc",
		ListOptions: gitea.ListOptions{
			Page:     1,
			PageSize: 50,
		},
	}

	for {
		repos, resp, err := s.options.Client.SearchRepos(opt)
		if err != nil {
			log.Error().Err(err).Msg("Failed searching repositories")
			return
		}

		for _, repo := range repos {
			log.Debug().Str("name", repo.Name).Str("url", repo.HTMLURL).Msg("Scan")
			s.scanRepository(repo)
		}

		if resp == nil || opt.Page >= resp.LastPage {
			break
		}
		opt.Page++
	}
}

func (s *giteaScanner) scanOwnedRepositories() {
	opt := gitea.ListReposOptions{
		ListOptions: gitea.ListOptions{
			Page:     1,
			PageSize: 50,
		},
	}

	username, _, err := s.options.Client.GetMyUserInfo()
	if err != nil {
		log.Error().Err(err).Msg("Failed getting user info")
		return
	}

	for {
		repos, resp, err := s.options.Client.ListUserRepos(username.UserName, opt)
		if err != nil {
			log.Error().Err(err).Msg("Failed fetching user repos")
			return
		}

		ownedRepos := make([]*gitea.Repository, 0)
		for _, repo := range repos {
			if repo.Owner != nil && repo.Owner.UserName == username.UserName {
				ownedRepos = append(ownedRepos, repo)
			}
		}

		for _, repo := range ownedRepos {
			log.Debug().Str("name", repo.Name).Str("url", repo.HTMLURL).Msg("Scan")
			s.scanRepository(repo)
		}

		if resp == nil || opt.Page >= resp.LastPage {
			break
		}
		opt.Page++
	}
}

func (s *giteaScanner) scanOrganizationRepositories(orgName string) {
	opt := gitea.ListOrgReposOptions{
		ListOptions: gitea.ListOptions{
			Page:     1,
			PageSize: 50,
		},
	}

	for {
		repos, resp, err := s.options.Client.ListOrgRepos(orgName, opt)
		if err != nil {
			log.Error().Err(err).Str("organization", orgName).Msg("Failed fetching organization repos")
			return
		}

		for _, repo := range repos {
			log.Debug().Str("name", repo.Name).Str("url", repo.HTMLURL).Msg("Scan")
			s.scanRepository(repo)
		}

		if resp == nil || opt.Page >= resp.LastPage {
			break
		}
		opt.Page++
	}
}

func (s *giteaScanner) scanRepository(repo *gitea.Repository) {
	if repo == nil {
		log.Error().Msg("Cannot scan repository: repository is nil")
		return
	}

	workflowRuns, err := listWorkflowRuns(s.options.Client, repo)
	if err != nil {
		// Check if it's a 403 error - API and UI access rights not yet synchronized
		if strings.Contains(err.Error(), "403") && s.options.Cookie != "" {
			log.Debug().Str("repo", repo.FullName).Msg("API returned 403, falling back to HTML scraping with cookie")
			scanRepositoryWithCookie(repo)
			return
		}
		log.Error().Err(err).Str("repo", repo.FullName).Msg("failed to list workflow runs")
		return
	}

	if len(workflowRuns) == 0 {
		log.Debug().Str("repo", repo.FullName).Msg("No workflow runs found")
		return
	}

	if s.options.StartRunID > 0 {
		filteredRuns := make([]ActionWorkflowRun, 0)
		for _, run := range workflowRuns {
			if run.ID <= s.options.StartRunID {
				filteredRuns = append(filteredRuns, run)
			}
		}
		workflowRuns = filteredRuns

		if len(workflowRuns) == 0 {
			log.Debug().Str("repo", repo.FullName).Int64("start_run_id", s.options.StartRunID).Msg("No workflow runs found with ID <= start-run-id")
			return
		}

		log.Info().Str("repo", repo.FullName).Int("runs", len(workflowRuns)).Int64("start_run_id", s.options.StartRunID).Msg("Found workflow runs from specified run ID")
	} else {
		log.Info().Str("repo", repo.FullName).Int("runs", len(workflowRuns)).Msg("Found workflow runs")
	}

	for _, run := range workflowRuns {
		log.Debug().
			Str("repo", repo.FullName).
			Int64("run_id", run.ID).
			Str("status", run.Status).
			Str("name", run.Name).
			Msg("scanning pipeline run")

		scanWorkflowRunLogs(s.options.Client, repo, run)

		if s.options.Artifacts {
			scanWorkflowArtifacts(s.options.Client, repo, run)
		}
	}
}

// InitializeOptions prepares scan options from CLI parameters.
func InitializeOptions(token, giteaURL, repository, organization, cookie, maxArtifactSizeStr string,
	owned, artifacts, truffleHogVerification bool,
	runsLimit int, startRunID int64, maxScanGoRoutines int, confidenceFilter []string, hitTimeout time.Duration) (ScanOptions, error) {

	_, err := url.ParseRequestURI(giteaURL)
	if err != nil {
		return ScanOptions{}, err
	}

	byteSize, err := format.ParseHumanSize(maxArtifactSizeStr)
	if err != nil {
		return ScanOptions{}, err
	}

	ctx := context.Background()

	authHeaders := map[string]string{"Authorization": "token " + token}

	var httpClient *resty.Client
	if cookie != "" {
		// #nosec G124 - Cookie attributes (Secure/HttpOnly/SameSite) are server-side browser directives; not applicable for client HTTP requests
		httpClient = httpclient.GetPipeleekHTTPClient(
			giteaURL,
			[]*http.Cookie{
				{
					Name:   "i_like_gitea",
					Value:  cookie,
					Path:   "/",
					Domain: "",
				},
			},
			authHeaders,
		)
	} else {
		// Auth header passed as defaultHeaders; Resty sets them on every request.
		// The Pipeleek transport (TLS, proxy, SOCKS) is preserved.
		httpClient = httpclient.GetPipeleekHTTPClient("", nil, authHeaders)
	}

	// Inject the Pipeleek standard client into the Gitea SDK so it shares the same
	// TLS/proxy/SOCKS settings. Auth is handled by gitea.SetToken; no auth headers
	// are passed here to avoid duplication.
	baseStandardClient := httpclient.GetPipeleekHTTPClient("", nil, nil).Client()
	client, err := gitea.NewClient(giteaURL, gitea.SetToken(token), gitea.SetHTTPClient(baseStandardClient))
	if err != nil {
		return ScanOptions{}, err
	}

	return ScanOptions{
		Token:                  token,
		GiteaURL:               giteaURL,
		Artifacts:              artifacts,
		ConfidenceFilter:       confidenceFilter,
		MaxScanGoRoutines:      maxScanGoRoutines,
		TruffleHogVerification: truffleHogVerification,
		Owned:                  owned,
		Organization:           organization,
		Repository:             repository,
		Cookie:                 cookie,
		RunsLimit:              runsLimit,
		StartRunID:             startRunID,
		MaxArtifactSize:        byteSize,
		HitTimeout:             hitTimeout,
		Context:                ctx,
		Client:                 client,
		HttpClient:             httpClient,
	}, nil
}

// ValidateCookie validates the provided cookie by making a test request.
func ValidateCookie(opts ScanOptions) error {
	// Set the global scanOptions for helper functions
	scanOptions = opts

	// Call the internal validateCookie function from html.go
	validateCookie()
	return nil
}
