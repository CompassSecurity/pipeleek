package scan

import (
	"context"
	"strconv"
	"time"

	bburl "github.com/CompassSecurity/pipeleek/pkg/bitbucket/url"
	"github.com/CompassSecurity/pipeleek/pkg/format"
	"github.com/CompassSecurity/pipeleek/pkg/scan/logline"
	"github.com/CompassSecurity/pipeleek/pkg/scan/result"
	"github.com/CompassSecurity/pipeleek/pkg/scan/runner"
	pkgscanner "github.com/CompassSecurity/pipeleek/pkg/scanner"
	"github.com/h2non/filetype"
	"github.com/rs/zerolog/log"
)

// ScanOptions contains configuration options for BitBucket scanning operations.
type ScanOptions struct {
	Email               string
	AccessToken         string
	ConfidenceFilter    []string
	MaxScanGoRoutines   int
	SecretsVerification bool
	MaxPipelines        int
	Workspace           string
	Owned               bool
	Public              bool
	After               string
	Artifacts           bool
	BitBucketURL        string
	MaxArtifactSize     int64
	HitTimeout          time.Duration
	Context             context.Context
	Client              BitBucketApiClient
	HasProvidedCookie   bool
}

type Scanner interface {
	pkgscanner.BaseScanner
}

type bbScanner struct {
	options ScanOptions
}

var _ pkgscanner.BaseScanner = (*bbScanner)(nil)

func NewScanner(opts ScanOptions) Scanner {
	return &bbScanner{
		options: opts,
	}
}

// Scan performs the BitBucket scanning operation based on the configured options.
func (s *bbScanner) Scan() error {
	runner.InitScanner(s.options.ConfidenceFilter)

	if s.options.HasProvidedCookie {
		s.options.Client.GetuserInfo()
	}

	if s.options.Public {
		log.Info().Msg("Scanning public repos")
		s.scanPublic(s.options.After)
	} else if s.options.Owned {
		log.Info().Msg("Scanning current user owned workspaces")
		s.scanOwned()
	} else if s.options.Workspace != "" {
		log.Info().Str("name", s.options.Workspace).Msg("Scanning a workspace")
		s.scanWorkspace(s.options.Workspace)
	} else {
		log.Error().Msg("Specify a scan mode --public, --owned, --workspace")
	}

	log.Info().Msg("Scan Finished, Bye Bye 🏳️‍🌈🔥")
	return nil
}

func (s *bbScanner) scanOwned() {
	next := ""
	for {
		workspaces, nextUrl, _, err := s.options.Client.ListOwnedWorkspaces(next)
		if err != nil {
			log.Error().Err(err).Msg("Failed fetching workspaces")
		}

		for _, workspace := range workspaces {
			log.Trace().Str("name", workspace.Name).Msg("Workspace")
			s.listWorkspaceRepos(workspace.Slug)
		}

		if nextUrl == "" {
			break
		}
		next = nextUrl
	}
}

func (s *bbScanner) scanWorkspace(workspace string) {
	next := ""
	for {
		repos, nextUrl, _, err := s.options.Client.ListWorkspaceRepositoires(next, workspace)
		if err != nil {
			log.Error().Err(err).Msg("Failed fetching workspace")
		}

		for _, repo := range repos {
			log.Debug().Str("url", repo.Links.HTML.Href).Time("created", repo.CreatedOn).Time("updated", repo.UpdatedOn).Msg("Repo")
			s.listRepoPipelines(workspace, repo.Name)
		}

		if nextUrl == "" {
			break
		}
		next = nextUrl
	}
}

func (s *bbScanner) scanPublic(after string) {
	afterTime := time.Time{}
	if after != "" {
		afterTime = format.ParseISO8601(after)
	}
	log.Info().Time("after", afterTime).Msg("Scanning repos after")
	next := ""
	for {
		repos, nextUrl, _, err := s.options.Client.ListPublicRepositories(next, afterTime)
		if err != nil {
			log.Error().Err(err).Msg("Failed fetching public repositories")
		}

		for _, repo := range repos {
			log.Debug().Str("url", repo.Links.HTML.Href).Time("created", repo.CreatedOn).Time("updated", repo.UpdatedOn).Msg("Repo")
			s.listRepoPipelines(repo.Workspace.Name, repo.Name)
		}

		if nextUrl == "" {
			break
		}
		next = nextUrl
	}
}

func (s *bbScanner) listWorkspaceRepos(workspaceSlug string) {
	next := ""
	for {
		repos, nextUrl, _, err := s.options.Client.ListWorkspaceRepositoires(next, workspaceSlug)
		if err != nil {
			log.Error().Err(err).Msg("Failed fetching workspace repos")
		}

		for _, repo := range repos {
			log.Debug().Str("url", repo.Links.HTML.Href).Time("created", repo.CreatedOn).Time("updated", repo.UpdatedOn).Msg("Repo")
			s.listRepoPipelines(workspaceSlug, repo.Name)
		}
		if nextUrl == "" {
			break
		}
		next = nextUrl
	}
}

func (s *bbScanner) listRepoPipelines(workspaceSlug string, repoSlug string) {
	pipelineCount := 0
	next := ""
	for {
		pipelines, nextUrl, _, err := s.options.Client.ListRepositoryPipelines(next, workspaceSlug, repoSlug)
		if err != nil {
			log.Error().Err(err).Msg("Failed fetching repo pipelines")
		}

		for _, pipeline := range pipelines {
			log.Trace().Int("buildNr", pipeline.BuildNumber).Str("uuid", pipeline.UUID).Msg("Pipeline")
			s.listPipelineSteps(workspaceSlug, repoSlug, pipeline.UUID)
			if s.options.Artifacts {
				log.Trace().Int("buildNr", pipeline.BuildNumber).Str("uuid", pipeline.UUID).Msg("Fetch pipeline artifacts")
				s.listArtifacts(workspaceSlug, repoSlug, pipeline.BuildNumber)
				s.listDownloadArtifacts(workspaceSlug, repoSlug)
			}

			pipelineCount = pipelineCount + 1
			if pipelineCount >= s.options.MaxPipelines && s.options.MaxPipelines > 0 {
				log.Debug().Str("workspace", workspaceSlug).Str("repo", repoSlug).Msg("Reached max pipelines runs, skip remaining")
				return
			}
		}

		if nextUrl == "" {
			break
		}
		next = nextUrl
	}
}

func (s *bbScanner) listArtifacts(workspaceSlug string, repoSlug string, buildId int) {
	next := ""
	for {
		artifacts, nextUrl, _, err := s.options.Client.ListPipelineArtifacts(next, workspaceSlug, repoSlug, buildId)
		if err != nil {
			log.Error().Err(err).Msg("Failed fetching pipeline download artifacts")
		}

		for _, art := range artifacts {
			if int64(art.FileSizeBytes) > s.options.MaxArtifactSize {
				log.Debug().
					Int("bytes", art.FileSizeBytes).
					Int64("maxBytes", s.options.MaxArtifactSize).
					Str("name", art.Name).
					Int("buildId", buildId).
					Msg("Skipped large pipeline artifact")
				continue
			}

			log.Trace().Str("name", art.Name).Msg("Pipeline Artifact")
			artifactBytes := s.options.Client.GetPipelineArtifact(workspaceSlug, repoSlug, buildId, art.UUID)

			if filetype.IsArchive(artifactBytes) {
				pkgscanner.HandleArchiveArtifact(art.Name, artifactBytes, s.buildWebArtifactUrl(workspaceSlug, repoSlug, buildId, art.StepUUID), "Build "+strconv.Itoa(buildId), s.options.SecretsVerification, s.options.HitTimeout)
			}
		}

		if nextUrl == "" {
			break
		}
		next = nextUrl
	}
}

func (s *bbScanner) listDownloadArtifacts(workspaceSlug string, repoSlug string) {
	next := ""
	for {
		downloadArtifacts, nextUrl, _, err := s.options.Client.ListDownloadArtifacts(next, workspaceSlug, repoSlug)
		if err != nil {
			log.Error().Err(err).Msg("Failed fetching pipeline download artifacts")
		}

		for _, artifact := range downloadArtifacts {
			if int64(artifact.Size) > s.options.MaxArtifactSize {
				log.Debug().
					Int("bytes", artifact.Size).
					Int64("maxBytes", s.options.MaxArtifactSize).
					Str("name", artifact.Name).
					Msg("Skipped large download artifact")
				continue
			}

			log.Trace().Str("name", artifact.Name).Str("creator", artifact.User.DisplayName).Msg("Download Artifact")
			s.getDownloadArtifact(artifact.Links.Self.Href, s.constructDownloadArtifactWebUrl(workspaceSlug, repoSlug, artifact.Name), artifact.Name)
		}

		if nextUrl == "" {
			break
		}
		next = nextUrl
	}
}

func (s *bbScanner) listPipelineSteps(workspaceSlug string, repoSlug string, pipelineUuid string) {
	next := ""
	for {
		steps, nextUrl, _, err := s.options.Client.ListPipelineSteps(next, workspaceSlug, repoSlug, pipelineUuid)
		if err != nil {
			log.Error().Err(err).Msg("Failed fetching pipeline steps")
		}

		for _, step := range steps {
			log.Trace().Str("step", step.UUID).Msg("Step")
			s.getSteplog(workspaceSlug, repoSlug, pipelineUuid, step.UUID)
		}

		if nextUrl == "" {
			break
		}
		next = nextUrl
	}
}

func (s *bbScanner) constructDownloadArtifactWebUrl(workspaceSlug string, repoSlug string, artifactName string) string {
	baseWebURL := bburl.GetWebBaseURL(s.options.BitBucketURL)
	webURL, err := bburl.BuildDownloadArtifactWebURL(baseWebURL, workspaceSlug, repoSlug, artifactName)
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to build artifact download URL")
	}
	return webURL
}

func (s *bbScanner) buildWebArtifactUrl(workspaceSlug string, repoSlug string, buildId int, stepUUID string) string {
	baseWebURL := bburl.GetWebBaseURL(s.options.BitBucketURL)
	return bburl.BuildPipelineStepArtifactURL(baseWebURL, workspaceSlug, repoSlug, buildId, stepUUID)
}

func (s *bbScanner) getSteplog(workspaceSlug string, repoSlug string, pipelineUuid string, stepUUID string) {
	logBytes, _, err := s.options.Client.GetStepLog(workspaceSlug, repoSlug, pipelineUuid, stepUUID)
	if err != nil {
		log.Error().Err(err).Msg("Failed fetching pipeline steps")
	}

	logResult, err := logline.ProcessLogs(logBytes, logline.ProcessOptions{
		MaxGoRoutines:     s.options.MaxScanGoRoutines,
		VerifyCredentials: s.options.SecretsVerification,
		HitTimeout:        s.options.HitTimeout,
	})
	if err != nil {
		log.Debug().Err(err).Str("stepUUid", stepUUID).Msg("Failed detecting secrets")
		return
	}

	baseWebURL := bburl.GetWebBaseURL(s.options.BitBucketURL)
	runURL := bburl.BuildPipelineStepURL(baseWebURL, workspaceSlug, repoSlug, pipelineUuid, stepUUID)
	result.ReportFindings(logResult.Findings, result.ReportOptions{
		LocationURL: runURL,
	})
}

func (s *bbScanner) getDownloadArtifact(downloadUrl string, webUrl string, filename string) {
	fileBytes := s.options.Client.GetDownloadArtifact(downloadUrl)
	if len(fileBytes) == 0 {
		return
	}

	if filetype.IsArchive(fileBytes) {
		pkgscanner.HandleArchiveArtifact(filename, fileBytes, webUrl, "Download Artifact", s.options.SecretsVerification, s.options.HitTimeout)
	} else {
		pkgscanner.DetectFileHits(fileBytes, webUrl, "Download Artifact", filename, "", s.options.SecretsVerification, s.options.HitTimeout)
	}
}

// InitializeOptions prepares scan options from CLI parameters.
func InitializeOptions(email, accessToken, bitBucketCookie, bitBucketURL, workspace, after, maxArtifactSizeStr string,
	owned, public, artifacts, secretsVerification bool,
	maxPipelines, maxScanGoRoutines int, confidenceFilter []string, hitTimeout time.Duration) (ScanOptions, error) {

	byteSize, err := format.ParseHumanSize(maxArtifactSizeStr)
	if err != nil {
		return ScanOptions{}, err
	}

	ctx := context.Background()
	client := NewClient(email, accessToken, bitBucketCookie, bitBucketURL)

	return ScanOptions{
		Email:               email,
		AccessToken:         accessToken,
		ConfidenceFilter:    confidenceFilter,
		MaxScanGoRoutines:   maxScanGoRoutines,
		SecretsVerification: secretsVerification,
		MaxPipelines:        maxPipelines,
		Workspace:           workspace,
		Owned:               owned,
		Public:              public,
		After:               after,
		Artifacts:           artifacts,
		BitBucketURL:        bitBucketURL,
		MaxArtifactSize:     byteSize,
		HitTimeout:          hitTimeout,
		Context:             ctx,
		Client:              client,
		HasProvidedCookie:   bitBucketCookie != "",
	}, nil
}
