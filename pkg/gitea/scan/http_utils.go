package gitea

import (
	"fmt"
	"net/url"

	"code.gitea.io/sdk/gitea"
	"github.com/rs/zerolog/log"
)

type httpResponse struct {
	Body          []byte
	StatusCode    int
	ContentLength int64
}

func makeHTTPGetRequest(url string) (*httpResponse, error) {
	if scanOptions.HttpClient == nil {
		return nil, fmt.Errorf("HTTP client is not initialized")
	}

	resp, err := scanOptions.HttpClient.R().Get(url)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}

	if resp == nil {
		return nil, fmt.Errorf("HTTP response is nil")
	}

	return &httpResponse{
		Body:          resp.Bytes(),
		StatusCode:    resp.StatusCode(),
		ContentLength: resp.RawResponse.ContentLength,
	}, nil
}

func makeHTTPPostRequest(urlStr string, body []byte, headers map[string]string) (*httpResponse, error) {
	if scanOptions.HttpClient == nil {
		return nil, fmt.Errorf("HTTP client is not initialized")
	}

	resp, err := scanOptions.HttpClient.R().
		SetBody(body).
		SetHeaders(headers).
		Post(urlStr)
	if err != nil {
		return nil, fmt.Errorf("HTTP POST request failed: %w", err)
	}

	if resp == nil {
		return nil, fmt.Errorf("HTTP response is nil")
	}

	return &httpResponse{
		Body:       resp.Bytes(),
		StatusCode: resp.StatusCode(),
	}, nil
}

func buildGiteaURL(pathFormat string, args ...interface{}) (string, error) {
	link, err := url.Parse(scanOptions.GiteaURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse Gitea URL: %w", err)
	}
	link.Path = fmt.Sprintf(pathFormat, args...)
	return link.String(), nil
}

func buildAPIURL(repo *gitea.Repository, pathFormat string, pathArgs ...interface{}) (string, error) {
	if repo == nil {
		return "", fmt.Errorf("repository is nil")
	}

	if repo.Owner == nil {
		return "", fmt.Errorf("repository owner is nil")
	}

	link, err := url.Parse(scanOptions.GiteaURL)
	if err != nil {
		return "", err
	}

	basePath := fmt.Sprintf("/api/v1/repos/%s/%s", repo.Owner.UserName, repo.Name)
	link.Path = basePath + fmt.Sprintf(pathFormat, pathArgs...)

	return link.String(), nil
}

type logContext struct {
	Repo  string
	RunID int64
	JobID int64
}

func logHTTPError(statusCode int, operation string, ctx logContext) {
	event := log.Error().Int("status", statusCode)

	if ctx.Repo != "" {
		event = event.Str("repo", ctx.Repo)
	}
	if ctx.RunID > 0 {
		event = event.Int64("run_id", ctx.RunID)
	}
	if ctx.JobID > 0 {
		event = event.Int64("job_id", ctx.JobID)
	}

	event.Msgf("failed to %s", operation)
}

func checkHTTPStatus(statusCode int, operation string) error {
	switch statusCode {
	case 200:
		return nil
	case 404:
		return fmt.Errorf("resource not found (404)")
	case 403:
		return fmt.Errorf("access forbidden (403)")
	case 410:
		return fmt.Errorf("resource gone (410)")
	default:
		if statusCode >= 400 {
			return fmt.Errorf("HTTP error: %d", statusCode)
		}
		return nil
	}
}
