package scan

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/format"
	"github.com/CompassSecurity/pipeleek/pkg/logging"
	"github.com/CompassSecurity/pipeleek/pkg/scan/logline"
	"github.com/CompassSecurity/pipeleek/pkg/scan/result"
	"github.com/CompassSecurity/pipeleek/pkg/scan/runner"
	pkgscanner "github.com/CompassSecurity/pipeleek/pkg/scanner"
	"github.com/bndr/gojenkins"
	"github.com/h2non/filetype"
	"github.com/rs/zerolog/log"
)

type ScanOptions struct {
	Username               string
	Token                  string
	JenkinsURL             string
	Folder                 string
	Job                    string
	MaxBuilds              int
	Artifacts              bool
	MaxArtifactSize        int64
	ConfidenceFilter       []string
	MaxScanGoRoutines      int
	TruffleHogVerification bool
	HitTimeout             time.Duration
	Context                context.Context
	Client                 JenkinsClient
}

type Scanner interface {
	pkgscanner.BaseScanner
}

type jenkinsScanner struct {
	options ScanOptions
}

var _ pkgscanner.BaseScanner = (*jenkinsScanner)(nil)

func NewScanner(opts ScanOptions) Scanner {
	return &jenkinsScanner{options: opts}
}

func (s *jenkinsScanner) Scan() error {
	runner.InitScanner(s.options.ConfidenceFilter)

	log.Debug().Str("url", s.options.JenkinsURL).Msg("Connecting to Jenkins")
	if err := s.options.Client.Init(s.options.Context); err != nil {
		return fmt.Errorf("failed initializing Jenkins client: %w", err)
	}
	log.Debug().Str("url", s.options.JenkinsURL).Msg("Connected to Jenkins")

	if s.options.Job != "" {
		log.Debug().Str("job", s.options.Job).Msg("Scanning single job")
		return s.scanJobByPath(s.options.Job)
	}

	if s.options.Folder != "" {
		log.Debug().Str("folder", s.options.Folder).Msg("Enumerating jobs in folder")
		jobs, err := s.collectJobsFromFolder(s.options.Folder)
		if err != nil {
			return err
		}
		log.Debug().Int("count", len(jobs)).Str("folder", s.options.Folder).Msg("Jobs collected from folder")
		s.scanJobs(jobs)
		log.Info().Msg("Scan Finished, Bye Bye 🏳️‍🌈🔥")
		return nil
	}

	log.Debug().Msg("Enumerating all root jobs")
	jobs, err := s.collectAllJobs()
	if err != nil {
		return err
	}
	log.Debug().Int("count", len(jobs)).Msg("Jobs collected")
	s.scanJobs(jobs)

	log.Info().Msg("Scan Finished, Bye Bye 🏳️‍🌈🔥")
	return nil
}

func (s *jenkinsScanner) collectAllJobs() ([]string, error) {
	entries, err := s.options.Client.ListRootJobs(s.options.Context)
	if err != nil {
		return nil, fmt.Errorf("failed listing Jenkins root jobs: %w", err)
	}
	log.Debug().Int("entries", len(entries)).Msg("Fetched root job entries")

	jobs := make([]string, 0)
	for _, entry := range entries {
		jobs = append(jobs, s.collectJobPathsRecursive(entry, "")...)
	}

	return dedupeAndSort(jobs), nil
}

func (s *jenkinsScanner) collectJobsFromFolder(folderPath string) ([]string, error) {
	entries, err := s.options.Client.ListFolderJobs(s.options.Context, folderPath)
	if err != nil {
		return nil, fmt.Errorf("failed listing folder jobs: %w", err)
	}
	log.Debug().Int("entries", len(entries)).Str("folder", folderPath).Msg("Fetched folder job entries")

	jobs := make([]string, 0)
	for _, entry := range entries {
		jobs = append(jobs, s.collectJobPathsRecursive(entry, strings.Trim(folderPath, "/"))...)
	}

	return dedupeAndSort(jobs), nil
}

func (s *jenkinsScanner) collectJobPathsRecursive(entry gojenkins.InnerJob, parent string) []string {
	path := joinJenkinsPath(parent, entry.Name)
	if isFolderClass(entry.Class) {
		log.Debug().Str("folder", path).Msg("Traversing folder")
		children, err := s.options.Client.ListFolderJobs(s.options.Context, path)
		if err != nil {
			log.Warn().Err(err).Str("folder", path).Msg("Failed to enumerate folder, skipping")
			return nil
		}

		jobs := make([]string, 0)
		for _, child := range children {
			jobs = append(jobs, s.collectJobPathsRecursive(child, path)...)
		}
		return jobs
	}

	log.Trace().Str("job", path).Msg("Discovered job")
	return []string{path}
}

func (s *jenkinsScanner) scanJobs(jobPaths []string) {
	for _, jobPath := range jobPaths {
		_ = s.scanJobByPath(jobPath) // ignore error since we already logged it
	}
}

func (s *jenkinsScanner) scanJobByPath(jobPath string) error {
	job, err := s.options.Client.GetJob(s.options.Context, jobPath)
	if err != nil {
		log.Warn().Err(err).Str("job", jobPath).Msg("Failed loading job, skipping")
		return nil
	}

	log.Info().Str("job", job.Raw.FullName).Msg("Scanning Jenkins job")

	s.scanJobDefinition(jobPath, job)
	s.scanBuilds(jobPath, job)
	return nil
}

func (s *jenkinsScanner) scanJobDefinition(jobPath string, job *gojenkins.Job) {
	configXML, err := s.options.Client.GetJobConfigXML(s.options.Context, jobPath)
	if err != nil {
		log.Debug().Err(err).Str("job", jobPath).Msg("Failed fetching job definition")
		return
	}

	findings, err := pkgscanner.DetectHits([]byte(configXML), s.options.MaxScanGoRoutines, s.options.TruffleHogVerification, s.options.HitTimeout)
	if err != nil {
		log.Debug().Err(err).Str("job", jobPath).Msg("Failed scanning job definition")
		return
	}

	result.ReportFindings(findings, result.ReportOptions{
		LocationURL: job.Raw.URL,
		JobName:     job.Raw.FullName,
		BuildName:   "config.xml",
	})
}

func (s *jenkinsScanner) scanBuilds(jobPath string, job *gojenkins.Job) {
	builds, err := job.GetAllBuildIds(s.options.Context)
	if err != nil {
		log.Debug().Err(err).Str("job", jobPath).Msg("Failed listing builds for job")
		return
	}

	sort.Slice(builds, func(i, j int) bool { return builds[i].Number > builds[j].Number })
	if s.options.MaxBuilds > 0 && len(builds) > s.options.MaxBuilds {
		log.Debug().Str("job", jobPath).Int("total", len(builds)).Int("limit", s.options.MaxBuilds).Msg("Limiting builds to scan")
		builds = builds[:s.options.MaxBuilds]
	} else {
		log.Debug().Str("job", jobPath).Int("count", len(builds)).Msg("Scanning builds")
	}

	for _, buildRef := range builds {
		log.Debug().Str("job", jobPath).Int64("build", buildRef.Number).Msg("Scanning build")
		build, err := s.options.Client.GetBuild(s.options.Context, jobPath, buildRef.Number)
		if err != nil {
			log.Debug().Err(err).Str("job", jobPath).Int64("build", buildRef.Number).Msg("Failed loading build")
			continue
		}

		s.scanBuildLogs(job, build)
		s.scanBuildEnvVars(job, build)
		if s.options.Artifacts {
			s.scanBuildArtifacts(job, build)
		}
	}
}

func (s *jenkinsScanner) scanBuildLogs(job *gojenkins.Job, build *gojenkins.Build) {
	log.Debug().Str("job", job.Raw.FullName).Int64("build", build.GetBuildNumber()).Msg("Scanning build logs")
	logOutput := build.GetConsoleOutput(s.options.Context)
	if logOutput == "" {
		log.Trace().Str("job", job.Raw.FullName).Int64("build", build.GetBuildNumber()).Msg("Build log is empty, skipping")
		return
	}

	logResult, err := logline.ProcessLogs([]byte(logOutput), logline.ProcessOptions{
		MaxGoRoutines:     s.options.MaxScanGoRoutines,
		VerifyCredentials: s.options.TruffleHogVerification,
		HitTimeout:        s.options.HitTimeout,
	})
	if err != nil {
		log.Debug().Err(err).Str("job", job.Raw.FullName).Int64("build", build.GetBuildNumber()).Msg("Failed detecting secrets in build logs")
		return
	}

	result.ReportFindings(logResult.Findings, result.ReportOptions{
		LocationURL: build.GetUrl(),
		JobName:     job.Raw.FullName,
		BuildName:   fmt.Sprintf("%d", build.GetBuildNumber()),
		Type:        logging.SecretTypeLog,
	})
}

func (s *jenkinsScanner) scanBuildEnvVars(job *gojenkins.Job, build *gojenkins.Build) {
	log.Debug().Str("job", job.Raw.FullName).Int64("build", build.GetBuildNumber()).Msg("Scanning injected env vars")
	envMap, err := build.GetInjectedEnvVars(s.options.Context)
	if err != nil || len(envMap) == 0 {
		log.Trace().Str("job", job.Raw.FullName).Int64("build", build.GetBuildNumber()).Msg("No injected env vars found")
		return
	}
	log.Debug().Str("job", job.Raw.FullName).Int64("build", build.GetBuildNumber()).Int("count", len(envMap)).Msg("Found injected env vars")

	builder := strings.Builder{}
	for key, value := range envMap {
		builder.WriteString(key)
		builder.WriteString("=")
		builder.WriteString(value)
		builder.WriteString("\n")
	}

	findings, err := pkgscanner.DetectHits([]byte(builder.String()), s.options.MaxScanGoRoutines, s.options.TruffleHogVerification, s.options.HitTimeout)
	if err != nil {
		log.Debug().Err(err).Str("job", job.Raw.FullName).Int64("build", build.GetBuildNumber()).Msg("Failed detecting secrets in build env vars")
		return
	}

	result.ReportFindings(findings, result.ReportOptions{
		LocationURL: build.GetUrl(),
		JobName:     job.Raw.FullName,
		BuildName:   fmt.Sprintf("%d env", build.GetBuildNumber()),
	})
}

func (s *jenkinsScanner) scanBuildArtifacts(job *gojenkins.Job, build *gojenkins.Build) {
	artifacts := build.GetArtifacts()
	if len(artifacts) == 0 {
		log.Trace().Str("job", job.Raw.FullName).Int64("build", build.GetBuildNumber()).Msg("No artifacts in build")
		return
	}
	log.Debug().Str("job", job.Raw.FullName).Int64("build", build.GetBuildNumber()).Int("count", len(artifacts)).Msg("Scanning build artifacts")

	for _, artifact := range artifacts {
		log.Trace().Str("job", job.Raw.FullName).Int64("build", build.GetBuildNumber()).Str("artifact", artifact.Path).Msg("Downloading artifact")
		artifactBytes, err := artifact.GetData(s.options.Context)
		if err != nil {
			log.Debug().Err(err).Str("job", job.Raw.FullName).Int64("build", build.GetBuildNumber()).Str("artifact", artifact.Path).Msg("Failed downloading artifact")
			continue
		}

		if int64(len(artifactBytes)) > s.options.MaxArtifactSize {
			log.Debug().
				Int("bytes", len(artifactBytes)).
				Int64("maxBytes", s.options.MaxArtifactSize).
				Str("artifact", artifact.Path).
				Msg("Skipped large artifact")
			continue
		}

		if filetype.IsArchive(artifactBytes) {
			pkgscanner.HandleArchiveArtifact(artifact.Path, artifactBytes, build.GetUrl(), fmt.Sprintf("Build %d", build.GetBuildNumber()), s.options.TruffleHogVerification, s.options.HitTimeout)
			continue
		}

		pkgscanner.DetectFileHits(artifactBytes, build.GetUrl(), fmt.Sprintf("Build %d", build.GetBuildNumber()), artifact.Path, "", s.options.TruffleHogVerification, s.options.HitTimeout)
	}
}

func InitializeOptions(username, token, jenkinsURL, folder, job, maxArtifactSizeStr string,
	artifacts, truffleHogVerification bool,
	maxBuilds, maxScanGoRoutines int, confidenceFilter []string, hitTimeout time.Duration) (ScanOptions, error) {

	byteSize, err := format.ParseHumanSize(maxArtifactSizeStr)
	if err != nil {
		return ScanOptions{}, err
	}

	ctx := context.Background()
	client := NewClient(jenkinsURL, username, token)

	return ScanOptions{
		Username:               username,
		Token:                  token,
		JenkinsURL:             jenkinsURL,
		Folder:                 folder,
		Job:                    job,
		MaxBuilds:              maxBuilds,
		Artifacts:              artifacts,
		MaxArtifactSize:        byteSize,
		ConfidenceFilter:       confidenceFilter,
		MaxScanGoRoutines:      maxScanGoRoutines,
		TruffleHogVerification: truffleHogVerification,
		HitTimeout:             hitTimeout,
		Context:                ctx,
		Client:                 client,
	}, nil
}

func dedupeAndSort(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, item := range in {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func isFolderClass(className string) bool {
	return strings.Contains(className, "folder") || strings.Contains(className, "Folder")
}

func joinJenkinsPath(base, name string) string {
	base = strings.Trim(base, "/")
	name = strings.Trim(name, "/")
	if base == "" {
		return name
	}
	return path.Join(base, name)
}
