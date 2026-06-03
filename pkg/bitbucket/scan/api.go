package scan

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path"
	"strconv"
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/httpclient"
	"github.com/rs/zerolog/log"

	"resty.dev/v3"
)

// Docs: https://developer.atlassian.com/cloud/bitbucket/rest/intro/
type BitBucketApiClient struct {
	Client          resty.Client
	BaseURL         string
	InternalBaseURL string
}

func NewClient(username string, password string, bitBucketCookie string, baseURL string) BitBucketApiClient {
	if baseURL == "" {
		baseURL = "https://api.bitbucket.org/2.0"
	}
	// Derive an internal base URL for BitBucket internal APIs (bitbucket.org/!api/...)
	// Default behaviour: if API base points to api.bitbucket.org use bitbucket.org for internal endpoints
	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to parse baseURL")
	}

	internalHost := parsedBase.Host
	if parsedBase.Host == "api.bitbucket.org" || parsedBase.Host == "api.bitbucket.org:443" {
		internalHost = "bitbucket.org"
	}
	internalBase := parsedBase.Scheme + "://" + internalHost + "/!api"

	client := *httpclient.GetPipeleekHTTPClient("", nil, nil).SetBasicAuth(username, password).SetRedirectPolicy(resty.FlexibleRedirectPolicy(5))
	if len(bitBucketCookie) > 0 {
		jar, _ := cookiejar.New(nil)
		// set cookie on the internal host root so requests to internal endpoints include it
		targetURL := &url.URL{Scheme: parsedBase.Scheme, Host: internalHost, Path: "/"}
		// #nosec G124 - Cookie attributes (Secure/HttpOnly/SameSite) are server-side browser directives; not applicable for client HTTP requests
		jar.SetCookies(targetURL, []*http.Cookie{
			{
				Name:  "cloud.session.token",
				Value: bitBucketCookie,
				Path:  "/!api",
			},
		})
		client.SetCookieJar(jar)
		log.Debug().Msg("Added cloud.session.token to HTTP client")
	}

	bbClient := BitBucketApiClient{Client: client, BaseURL: baseURL, InternalBaseURL: internalBase}
	bbClient.Client.AddRetryHooks(
		func(res *resty.Response, err error) {
			if res.StatusCode() == 429 {
				log.Info().Int("status", res.StatusCode()).Msg("Retrying request, we are rate limited")
			} else {
				log.Info().Int("status", res.StatusCode()).Msg("Retrying request, not due to rate limit")
			}
		},
	)
	return bbClient
}

// https://developer.atlassian.com/cloud/bitbucket/rest/api-group-workspaces/#api-workspaces-get
func (a BitBucketApiClient) ListOwnedWorkspaces(nextPageUrl string) ([]Workspace, string, *resty.Response, error) {
	url := a.BaseURL + "/workspaces"
	if nextPageUrl != "" {
		url = nextPageUrl
	}
	resp := &PaginatedResponse[Workspace]{}
	res, err := a.Client.R().
		SetQueryParam("sort", "-updated_on").
		SetResult(resp).
		Get(url)

	if err != nil {
		log.Error().Err(err).Str("url", url).Msg("Failed to list owned workspaces (network or client error)")
	}

	if res != nil && res.StatusCode() >= 400 {
		log.Error().Int("status", res.StatusCode()).Str("url", url).Str("response", res.String()).Msg("Failed to list owned workspaces (HTTP error)")
	}

	return resp.Values, resp.Next, res, err
}

// https://developer.atlassian.com/cloud/bitbucket/rest/api-group-repositories/#api-repositories-workspace-get
func (a BitBucketApiClient) ListWorkspaceRepositoires(nextPageUrl string, workspaceSlug string) ([]Repository, string, *resty.Response, error) {
	reqUrl := ""
	if nextPageUrl != "" {
		reqUrl = nextPageUrl
	} else {
		u, err := url.Parse(a.BaseURL + "/repositories/")
		if err != nil {
			log.Fatal().Err(err).Msg("Unable to parse ListWorkspaceRepositoires url")
		}
		u.Path = path.Join(u.Path, workspaceSlug)
		reqUrl = u.String()
	}

	resp := &PaginatedResponse[Repository]{}
	res, err := a.Client.R().
		SetQueryParam("sort", "-updated_on").
		SetResult(resp).
		Get(reqUrl)

	if err != nil {
		log.Error().Err(err).Str("url", reqUrl).Msg("Failed to list workspace repositories (network or client error)")
	}

	if res != nil && res.StatusCode() >= 400 {
		log.Error().Int("status", res.StatusCode()).Str("url", reqUrl).Str("response", res.String()).Msg("Failed to list workspace repositories (HTTP error)")
	}

	return resp.Values, resp.Next, res, err
}

// https://developer.atlassian.com/cloud/bitbucket/rest/api-group-repositories/#api-repositories-get
func (a BitBucketApiClient) ListPublicRepositories(nextPageUrl string, after time.Time) ([]PublicRepository, string, *resty.Response, error) {
	reqUrl := ""
	if nextPageUrl != "" {
		reqUrl = nextPageUrl
	} else {
		u, err := url.Parse(a.BaseURL + "/repositories/")
		if err != nil {
			log.Fatal().Err(err).Msg("Unable to parse ListPublicRepositories url")
		}
		reqUrl = u.String()
	}

	resp := &PaginatedResponse[PublicRepository]{}
	// only set it initially after that the next url does use the after query param for paging
	if nextPageUrl == "" {
		res, err := a.Client.R().SetResult(resp).SetQueryParam("after", after.Format(time.RFC3339)).Get(reqUrl)
		if err != nil {
			log.Error().Err(err).Str("url", reqUrl).Msg("Failed to list public repositories (network or client error)")
		}

		if res != nil && res.StatusCode() >= 400 {
			log.Error().Int("status", res.StatusCode()).Str("url", reqUrl).Str("response", res.String()).Msg("Failed to list public repositories (HTTP error)")
		}

		return resp.Values, resp.Next, res, err
	} else {
		res, err := a.Client.R().SetResult(resp).Get(reqUrl)
		if err != nil {
			log.Error().Err(err).Str("url", reqUrl).Msg("Failed to list public repositories (network or client error)")
		}

		if res != nil && res.StatusCode() >= 400 {
			log.Error().Int("status", res.StatusCode()).Str("url", reqUrl).Str("response", res.String()).Msg("Failed to list public repositories (HTTP error)")
		}
		return resp.Values, resp.Next, res, err
	}
}

// https://developer.atlassian.com/cloud/bitbucket/rest/api-group-pipelines/#api-repositories-workspace-repo-slug-pipelines-get
func (a BitBucketApiClient) ListRepositoryPipelines(nextPageUrl string, workspaceSlug string, repoSlug string) ([]Pipeline, string, *resty.Response, error) {
	reqUrl := ""
	if nextPageUrl != "" {
		reqUrl = nextPageUrl
	} else {
		u, err := url.Parse(a.BaseURL + "/repositories/")
		if err != nil {
			log.Fatal().Err(err).Msg("Unable to parse ListRepositoryPipelines url")
		}
		u.Path = path.Join(u.Path, workspaceSlug, repoSlug, "pipelines")
		reqUrl = u.String()
	}

	resp := &PaginatedResponse[Pipeline]{}
	res, err := a.Client.R().
		SetQueryParam("sort", "-created_on").
		SetResult(resp).
		Get(reqUrl)

	if err != nil {
		log.Error().Err(err).Str("url", reqUrl).Msg("Failed to list repository pipelines (network or client error)")
	}

	// if pipelines are not active silently continue
	if res != nil && res.StatusCode() == 404 {
		return resp.Values, resp.Next, res, err
	}

	if res != nil && res.StatusCode() >= 400 {
		log.Error().Int("status", res.StatusCode()).Str("url", reqUrl).Str("response", res.String()).Msg("Failed to list repository pipelines (HTTP error)")
	}

	return resp.Values, resp.Next, res, err
}

// https://developer.atlassian.com/cloud/bitbucket/rest/api-group-pipelines/#api-repositories-workspace-repo-slug-pipelines-pipeline-uuid-steps-get
func (a BitBucketApiClient) ListPipelineSteps(nextPageUrl string, workspaceSlug string, repoSlug string, pipelineUUID string) ([]PipelineStep, string, *resty.Response, error) {
	reqUrl := ""
	if nextPageUrl != "" {
		reqUrl = nextPageUrl
	} else {
		u, err := url.Parse(a.BaseURL + "/repositories/")
		if err != nil {
			log.Fatal().Err(err).Msg("Unable to parse ListPipelineSteps url")
		}
		u.Path = path.Join(u.Path, workspaceSlug, repoSlug, "pipelines", pipelineUUID, "steps")
		reqUrl = u.String()
	}

	resp := &PaginatedResponse[PipelineStep]{}
	res, err := a.Client.R().
		SetResult(resp).
		Get(reqUrl)

	if err != nil {
		log.Error().Err(err).Str("url", reqUrl).Msg("Failed to list pipeline steps (network or client error)")
	}

	if res != nil && res.StatusCode() >= 400 {
		log.Error().Int("status", res.StatusCode()).Str("url", reqUrl).Str("response", res.String()).Msg("Failed to list pipeline steps (HTTP error)")
	}

	return resp.Values, resp.Next, res, err
}

// https://developer.atlassian.com/cloud/bitbucket/rest/api-group-pipelines/#api-repositories-workspace-repo-slug-pipelines-pipeline-uuid-steps-step-uuid-log-get
func (a BitBucketApiClient) GetStepLog(workspaceSlug string, repoSlug string, pipelineUUID string, stepUUID string) ([]byte, *resty.Response, error) {
	u, err := url.Parse(a.BaseURL + "/repositories/")
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to parse GetStepLog url")
	}
	u.Path = path.Join(u.Path, workspaceSlug, repoSlug, "pipelines", pipelineUUID, "steps", stepUUID, "log")

	res, err := a.Client.R().
		Get(u.String())

	if err != nil {
		log.Error().Err(err).Str("url", u.String()).Msg("Failed to get step log (network or client error)")
	}

	// if step log is missing silently continue
	if res != nil && res.StatusCode() == 404 {
		return res.Bytes(), res, err
	}

	if res != nil && res.StatusCode() >= 400 {
		log.Error().Int("status", res.StatusCode()).Str("url", u.String()).Str("response", res.String()).Msg("Failed to get step log (HTTP error)")
	}

	return res.Bytes(), res, err
}

// https://developer.atlassian.com/cloud/bitbucket/rest/api-group-downloads/#api-repositories-workspace-repo-slug-downloads-get
func (a BitBucketApiClient) ListDownloadArtifacts(nextPageUrl string, workspaceSlug string, repoSlug string) ([]DownloadArtifact, string, *resty.Response, error) {
	reqUrl := ""
	if nextPageUrl != "" {
		reqUrl = nextPageUrl
	} else {
		u, err := url.Parse(a.BaseURL + "/repositories/")
		if err != nil {
			log.Fatal().Err(err).Msg("Unable to parse ListDownloadArtifacts url")
		}
		u.Path = path.Join(u.Path, workspaceSlug, repoSlug, "downloads")
		reqUrl = u.String()
	}

	resp := &PaginatedResponse[DownloadArtifact]{}
	res, err := a.Client.R().
		SetResult(resp).
		Get(reqUrl)

	if err != nil {
		log.Error().Err(err).Str("url", reqUrl).Msg("Failed to list download artifacts (network or client error)")
	}

	if res != nil && res.StatusCode() >= 400 {
		log.Error().Int("status", res.StatusCode()).Str("url", reqUrl).Str("response", res.String()).Msg("Failed to list download artifacts (HTTP error)")
	}

	return resp.Values, resp.Next, res, err
}

func (a BitBucketApiClient) GetDownloadArtifact(url string) []byte {
	res, err := a.Client.R().Get(url)
	if err != nil {
		log.Error().Err(err).Str("url", url).Msg("Failed downloading Download Artifact (network or client error)")
		return []byte{}
	}

	if res != nil && res.StatusCode() >= 400 {
		log.Error().Int("status", res.StatusCode()).Str("url", url).Str("response", res.String()).Msg("Failed downloading Download Artifact (HTTP error)")
		return []byte{}
	}

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		log.Error().Err(err).Str("url", url).Msg("Failed reading Download Artifact response")
		return []byte{}
	}

	return bodyBytes
}

// Internal API: https://bitbucket.org/!api/internal/repositories/{workspace}/{repo}/pipelines/{buildNumber}/artifacts
func (a BitBucketApiClient) ListPipelineArtifacts(nextPageUrl string, workspaceSlug string, repoSlug string, buildNumber int) ([]Artifact, string, *resty.Response, error) {
	reqUrl := ""
	if nextPageUrl != "" {
		reqUrl = nextPageUrl
	} else {
		u, err := url.Parse(a.InternalBaseURL + "/internal/repositories/")
		if err != nil {
			log.Fatal().Err(err).Msg("Unable to parse ListPipelineArtifacst url")
		}
		u.Path = path.Join(u.Path, workspaceSlug, repoSlug, "pipelines", strconv.Itoa(buildNumber), "artifacts")
		reqUrl = u.String()
	}

	resp := &PaginatedResponse[Artifact]{}
	res, err := a.Client.R().
		SetResult(resp).
		Get(reqUrl)

	return resp.Values, resp.Next, res, err
}

// Internal API: https://bitbucket.org/!api/internal/repositories/{workspace}/{repo}/pipelines/{buildId}/artifacts/{ArtifactUUID}/content
func (a BitBucketApiClient) GetPipelineArtifact(workspaceSlug string, repoSlug string, buildNumber int, artifactUUID string) []byte {
	u, err := url.Parse(a.InternalBaseURL + "/internal/repositories/")
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to parse GetPipelineArtifact url")
	}
	u.Path = path.Join(u.Path, workspaceSlug, repoSlug, "pipelines", strconv.Itoa(buildNumber), "artifacts", artifactUUID, "content")

	res, err := a.Client.R().Get(u.String())
	if err != nil {
		log.Error().Err(err).Str("url", u.String()).Msg("Failed downloading pipeline artifact")
		return []byte{}
	}

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		log.Error().Err(err).Str("url", u.String()).Msg("Failed reading pipeline artifact response")
		return []byte{}
	}

	return bodyBytes
}

// Internal API: GET https://bitbucket.org/!api/2.0/user/emails
func (a BitBucketApiClient) GetuserInfo() {
	resp := &UserInfo{}
	res, err := a.Client.R().
		SetResult(resp).
		Get(a.InternalBaseURL + "/2.0/user")

	if err != nil {
		log.Error().Err(err).Msg("Failed get user info (network or client error)")
	}

	if res != nil && res.StatusCode() != 200 {
		log.Fatal().Int("status", res.StatusCode()).Msg("Failed to get user info (HTTP error). Check your cookie supplied with the -c flag! See the help menu for more information.")
	}

	log.Info().Str("username", resp.Username).Str("type", resp.Type).Msg("BitBucket session cookie is valid")
}
