package scan

import (
	"crypto/tls"
	"net/url"
	"path"
	"strconv"

	"github.com/CompassSecurity/pipeleek/pkg/httpclient"
	"github.com/rs/zerolog/log"

	"resty.dev/v3"
)

// https://learn.microsoft.com/en-us/rest/api/azure/devops/
type AzureDevOpsApiClient struct {
	Client   resty.Client
	BaseURL  string
	VsspsURL string // URL for profile/account APIs
}

func NewClient(username string, password string, baseURL string) AzureDevOpsApiClient {
	if baseURL == "" {
		baseURL = "https://dev.azure.com"
	}
	// Azure DevOps is a cloud-only service (dev.azure.com) with a valid TLS certificate;
	// always enforce certificate verification regardless of the global --tls-verification flag.
	bbClient := AzureDevOpsApiClient{
		Client: *httpclient.GetPipeleekHTTPClient("", nil, nil).
			SetTLSClientConfig(&tls.Config{MinVersion: tls.VersionTLS12}).
			SetBasicAuth(username, password).
			SetRedirectPolicy(resty.FlexibleRedirectPolicy(5)),
		BaseURL:  baseURL,
		VsspsURL: "https://app.vssps.visualstudio.com",
	}
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

// https://learn.microsoft.com/en-us/rest/api/azure/devops/profile/profiles/get?view=azure-devops-rest-7.2&tabs=HTTP
func (a AzureDevOpsApiClient) GetAuthenticatedUser() (*AuthenticatedUser, *resty.Response, error) {
	u, err := url.Parse(a.VsspsURL + "/_apis/profile/profiles/me")
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to parse GetAuthenticatedUser url")
	}
	reqUrl := u.String()

	user := &AuthenticatedUser{}
	res, err := a.Client.R().
		SetQueryParam("api-version", "7.2-preview.3").
		SetResult(user).
		Get(reqUrl)

	if err != nil {
		log.Error().Err(err).Str("url", reqUrl).Msg("Failed fetching authenticated user (network or client error)")
	}

	if res != nil && res.StatusCode() > 400 {
		log.Error().Int("status", res.StatusCode()).Str("url", reqUrl).Str("response", res.String()).Msg("Failed fetching authenticated user (HTTP error)")
	}

	return user, res, err
}

// https://learn.microsoft.com/en-us/rest/api/azure/devops/account/accounts/list?view=azure-devops-rest-7.2&tabs=HTTP
func (a AzureDevOpsApiClient) ListAccounts(ownerId string) ([]Account, *resty.Response, error) {
	u, err := url.Parse(a.VsspsURL + "/_apis/accounts")
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to parse ListAccounts url")
	}
	reqUrl := u.String()

	resp := &PaginatedResponse[Account]{}
	res, err := a.Client.R().
		SetQueryParam("api-version", "7.2-preview.1").
		SetQueryParam("ownerId", ownerId).
		SetResult(resp).
		Get(reqUrl)

	if err != nil {
		log.Error().Err(err).Str("url", reqUrl).Msg("Fetching accounts failed (network or client error)")
	}

	if res != nil && res.StatusCode() > 400 {
		log.Error().Int("status", res.StatusCode()).Str("url", reqUrl).Str("ownerId", ownerId).Str("response", res.String()).Msg("Fetching accounts failed (HTTP error)")
	}

	return resp.Value, res, err
}

// https://learn.microsoft.com/en-us/rest/api/azure/devops/core/projects/list?view=azure-devops-rest-7.2&tabs=HTTP
func (a AzureDevOpsApiClient) ListProjects(continuationToken string, organization string) ([]Project, *resty.Response, string, error) {
	reqUrl := ""
	u, err := url.Parse(a.BaseURL + "/")
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to parse ListProjects url")
	}
	u.Path = path.Join(u.Path, organization, "_apis", "projects")
	reqUrl = u.String()

	resp := &PaginatedResponse[Project]{}
	res, err := a.Client.R().
		SetQueryParam("api-version", "7.2-preview.4").
		SetQueryParam("$top", "100").
		SetQueryParam("continuationtoken", continuationToken).
		SetResult(resp).
		Get(reqUrl)

	if err != nil {
		log.Error().Err(err).Str("url", reqUrl).Str("organization", organization).Msg("Failed to list projects (network or client error)")
	}

	if res != nil && (res.StatusCode() == 404 || res.StatusCode() == 401) {
		log.Error().Int("status", res.StatusCode()).Str("organization", organization).Str("url", reqUrl).Str("response", res.String()).Msg("Projects list does not exist or you do not have access (HTTP error)")
	}

	return resp.Value, res, res.Header().Get("x-ms-continuationtoken"), err
}

// https://learn.microsoft.com/en-us/rest/api/azure/devops/build/builds/list?view=azure-devops-rest-7.2
func (a AzureDevOpsApiClient) ListBuilds(continuationToken string, organization string, project string) ([]Build, *resty.Response, string, error) {
	reqUrl := ""
	u, err := url.Parse(a.BaseURL + "/")
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to parse ListBuilds url")
	}

	u.Path = path.Join(u.Path, organization, project, "_apis", "build", "builds")
	reqUrl = u.String()

	resp := &PaginatedResponse[Build]{}
	res, err := a.Client.R().
		SetQueryParam("api-version", "7.2-preview.7").
		SetQueryParam("$top", "100").
		SetQueryParam("continuationtoken", continuationToken).
		SetResult(resp).
		Get(reqUrl)

	if err != nil {
		log.Error().Err(err).Str("url", reqUrl).Str("organization", organization).Str("project", project).Msg("Failed to list builds (network or client error)")
	}

	if res != nil && (res.StatusCode() == 404 || res.StatusCode() == 401) {
		log.Error().Int("status", res.StatusCode()).Str("organization", organization).Str("project", project).Str("url", reqUrl).Str("response", res.String()).Msg("Build list does not exist or you do not have access (HTTP error)")
	}

	return resp.Value, res, res.Header().Get("x-ms-continuationtoken"), err
}

// https://learn.microsoft.com/en-us/rest/api/azure/devops/build/builds/get-build-logs?view=azure-devops-rest-7.2
// this endpoint is NOT paged
func (a AzureDevOpsApiClient) ListBuildLogs(organization string, project string, buildId int) ([]BuildLog, *resty.Response, error) {
	reqUrl := ""
	u, err := url.Parse(a.BaseURL + "/")
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to parse ListBuilds url")
	}

	u.Path = path.Join(u.Path, organization, project, "_apis", "build", "builds", strconv.Itoa(buildId), "logs")
	reqUrl = u.String()

	resp := &PaginatedResponse[BuildLog]{}
	res, err := a.Client.R().
		SetQueryParam("api-version", "7.2-preview.2").
		SetResult(resp).
		Get(reqUrl)

	if err != nil {
		log.Error().Err(err).Str("url", reqUrl).Str("organization", organization).Str("project", project).Msg("Failed to list build logs (network or client error)")
	}

	if res != nil && (res.StatusCode() == 404 || res.StatusCode() == 401) {
		log.Error().Int("status", res.StatusCode()).Str("organization", organization).Str("project", project).Str("url", reqUrl).Str("response", res.String()).Msg("Build log list does not exist or you do not have access (HTTP error)")
	}

	return resp.Value, res, err
}

// https://learn.microsoft.com/en-us/rest/api/azure/devops/build/builds/get-build-log?view=azure-devops-rest-7.2
func (a AzureDevOpsApiClient) GetLog(organization string, project string, buildId int, logId int) ([]byte, *resty.Response, error) {
	reqUrl := ""
	u, err := url.Parse(a.BaseURL + "/")
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to parse ListBuilds url")
	}

	u.Path = path.Join(u.Path, organization, project, "_apis", "build", "builds", strconv.Itoa(buildId), "logs", strconv.Itoa(logId))
	reqUrl = u.String()

	res, err := a.Client.R().
		SetQueryParam("api-version", "7.2-preview.2").
		Get(reqUrl)

	if err != nil {
		log.Error().Err(err).Str("url", reqUrl).Str("organization", organization).Str("project", project).Msg("Failed to get build log (network or client error)")
	}

	if res != nil && (res.StatusCode() == 404 || res.StatusCode() == 401) {
		log.Error().Int("status", res.StatusCode()).Str("organization", organization).Str("project", project).Str("url", reqUrl).Str("response", res.String()).Msg("Log does not exist or you do not have access (HTTP error)")
	}

	return res.Bytes(), res, err
}

func (a AzureDevOpsApiClient) DownloadArtifactZip(url string) ([]byte, *resty.Response, error) {
	res, err := a.Client.R().
		Get(url)

	if err != nil {
		log.Error().Err(err).Str("url", url).Msg("Failed downloading artifact zip (network or client error)")
	}

	if res != nil && (res.StatusCode() == 404 || res.StatusCode() == 401) {
		log.Error().Int("status", res.StatusCode()).Str("url", url).Str("response", res.String()).Msg("Failed downloading artifact zip (HTTP error)")
	}

	return res.Bytes(), res, err
}

// https://learn.microsoft.com/en-us/rest/api/azure/devops/build/artifacts/list?view=azure-devops-rest-7.1
// this endpoint is NOT paged
func (a AzureDevOpsApiClient) ListBuildArtifacts(continuationToken string, organization string, project string, buildId int) ([]Artifact, *resty.Response, string, error) {
	reqUrl := ""
	u, err := url.Parse(a.BaseURL + "/")
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to parse ListBuildArtifacts url")
	}

	u.Path = path.Join(u.Path, organization, project, "_apis", "build", "builds", strconv.Itoa(buildId), "artifacts")
	reqUrl = u.String()

	resp := &PaginatedResponse[Artifact]{}
	res, err := a.Client.R().
		SetQueryParam("api-version", "7.1").
		SetQueryParam("continuationtoken", continuationToken).
		SetResult(resp).
		Get(reqUrl)

	if err != nil {
		log.Error().Err(err).Str("url", reqUrl).Str("organization", organization).Str("project", project).Msg("Failed to list build artifacts (network or client error)")
	}

	if res != nil && (res.StatusCode() == 404 || res.StatusCode() == 401) {
		log.Error().Int("status", res.StatusCode()).Str("organization", organization).Str("project", project).Str("url", reqUrl).Str("response", res.String()).Msg("Build artifacts list does not exist or you do not have access (HTTP error)")
	}

	return resp.Value, res, res.Header().Get("x-ms-continuationtoken"), err
}
