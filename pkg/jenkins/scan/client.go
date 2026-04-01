package scan

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/bndr/gojenkins"
)

type JenkinsClient interface {
	Init(ctx context.Context) error
	ListRootJobs(ctx context.Context) ([]gojenkins.InnerJob, error)
	ListFolderJobs(ctx context.Context, folderPath string) ([]gojenkins.InnerJob, error)
	GetJob(ctx context.Context, jobPath string) (*gojenkins.Job, error)
	GetBuild(ctx context.Context, jobPath string, buildNumber int64) (*gojenkins.Build, error)
	GetJobConfigXML(ctx context.Context, jobPath string) (string, error)
}

type goJenkinsClient struct {
	jenkins *gojenkins.Jenkins
}

func NewClient(serverURL, username, token string) JenkinsClient {
	base := normalizeBaseURL(serverURL)
	jenkins := gojenkins.CreateJenkins(nil, base, username, token)
	return &goJenkinsClient{jenkins: jenkins}
}

func (c *goJenkinsClient) Init(ctx context.Context) error {
	_, err := c.jenkins.Init(ctx)
	return err
}

func (c *goJenkinsClient) ListRootJobs(ctx context.Context) ([]gojenkins.InnerJob, error) {
	return c.jenkins.GetAllJobNames(ctx)
}

func (c *goJenkinsClient) ListFolderJobs(ctx context.Context, folderPath string) ([]gojenkins.InnerJob, error) {
	segments := splitJenkinsPath(folderPath)
	if len(segments) == 0 {
		return nil, fmt.Errorf("folder path cannot be empty")
	}

	folder, err := c.jenkins.GetFolder(ctx, segments[len(segments)-1], segments[:len(segments)-1]...)
	if err != nil {
		return nil, err
	}

	return folder.Raw.Jobs, nil
}

func (c *goJenkinsClient) GetJob(ctx context.Context, jobPath string) (*gojenkins.Job, error) {
	segments := splitJenkinsPath(jobPath)
	if len(segments) == 0 {
		return nil, fmt.Errorf("job path cannot be empty")
	}
	return c.jenkins.GetJob(ctx, segments[len(segments)-1], segments[:len(segments)-1]...)
}

func (c *goJenkinsClient) GetBuild(ctx context.Context, jobPath string, buildNumber int64) (*gojenkins.Build, error) {
	job, err := c.GetJob(ctx, jobPath)
	if err != nil {
		return nil, err
	}
	return job.GetBuild(ctx, buildNumber)
}

func (c *goJenkinsClient) GetJobConfigXML(ctx context.Context, jobPath string) (string, error) {
	job, err := c.GetJob(ctx, jobPath)
	if err != nil {
		return "", err
	}

	var configXML string
	_, err = c.jenkins.Requester.GetXML(ctx, path.Join(job.Base, "config.xml"), &configXML, nil)
	if err != nil {
		return "", err
	}
	return configXML, nil
}

func normalizeBaseURL(serverURL string) string {
	trimmed := strings.TrimSpace(serverURL)
	if trimmed == "" {
		return "http://localhost:8080/"
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return trimmed
	}

	if parsed.Path == "" {
		parsed.Path = "/"
	}
	if !strings.HasSuffix(parsed.Path, "/") {
		parsed.Path += "/"
	}

	return parsed.String()
}

func splitJenkinsPath(path string) []string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if p := strings.TrimSpace(part); p != "" {
			result = append(result, p)
		}
	}
	return result
}
