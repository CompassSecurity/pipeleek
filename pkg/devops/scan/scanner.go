package scan

import (
	"context"
	"strconv"
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/format"
	artifactproc "github.com/CompassSecurity/pipeleek/pkg/scan/artifact"
	"github.com/CompassSecurity/pipeleek/pkg/scan/logline"
	"github.com/CompassSecurity/pipeleek/pkg/scan/result"
	"github.com/CompassSecurity/pipeleek/pkg/scan/runner"
	pkgscanner "github.com/CompassSecurity/pipeleek/pkg/scanner"
	"github.com/rs/zerolog/log"
)

// ScanOptions contains configuration options for Azure DevOps scanning operations.
type ScanOptions struct {
	Username            string
	AccessToken         string
	ConfidenceFilter    []string
	MaxScanGoRoutines   int
	SecretsVerification bool
	MaxBuilds           int
	Organization        string
	Project             string
	Artifacts           bool
	DevOpsURL           string
	MaxArtifactSize     int64
	HitTimeout          time.Duration
	Context             context.Context
	Client              AzureDevOpsApiClient
}

type Scanner interface {
	pkgscanner.BaseScanner
}

type devOpsScanner struct {
	options ScanOptions
}

var _ pkgscanner.BaseScanner = (*devOpsScanner)(nil)

func NewScanner(opts ScanOptions) Scanner {
	return &devOpsScanner{
		options: opts,
	}
}

// Scan performs the Azure DevOps scanning operation based on the configured options.
func (s *devOpsScanner) Scan() error {
	runner.InitScanner(s.options.ConfidenceFilter)

	if s.options.Organization == "" && s.options.Project == "" {
		s.scanAuthenticatedUser()
	} else if s.options.Organization != "" && s.options.Project == "" {
		s.scanOrganization(s.options.Organization)
	} else if s.options.Organization != "" && s.options.Project != "" {
		s.scanProject(s.options.Organization, s.options.Project)
	}

	log.Info().Msg("Scan Finished, Bye Bye 🏳️‍🌈🔥")
	return nil
}

func (s *devOpsScanner) scanAuthenticatedUser() {
	log.Info().Msg("Scanning authenticated user")

	user, _, err := s.options.Client.GetAuthenticatedUser()
	if err != nil {
		log.Error().Err(err).Msg("Failed fetching authenticated user")
	}

	log.Info().Str("displayName", user.DisplayName).Msg("Authenticated User")
	s.listAccounts(user.ID)
}

func (s *devOpsScanner) scanOrganization(organization string) {
	log.Info().Str("organization", organization).Msg("Scanning organization")
	s.listProjects(organization)
}

func (s *devOpsScanner) scanProject(organization string, project string) {
	log.Info().Str("organization", organization).Str("project", project).Msg("Scanning project")
	s.listBuilds(organization, project)
}

func (s *devOpsScanner) listAccounts(userId string) {
	accounts, _, err := s.options.Client.ListAccounts(userId)
	if err != nil {
		log.Fatal().Err(err).Str("userId", userId).Msg("Failed fetching accounts")
	}

	if len(accounts) == 0 {
		log.Info().Msg("No accounts found, check your token access scope!")
		return
	}

	for _, account := range accounts {
		log.Debug().Str("name", account.AccountName).Msg("Scanning Account")
		s.listProjects(account.AccountName)
	}
}

func (s *devOpsScanner) listProjects(organization string) {
	continuationToken := ""
	for {
		projects, _, ctoken, err := s.options.Client.ListProjects(continuationToken, organization)

		if err != nil {
			log.Fatal().Err(err).Str("organization", organization).Msg("Failed fetching projects")
		}

		for _, project := range projects {
			s.listBuilds(organization, project.Name)
		}

		if ctoken == "" {
			break
		}
		continuationToken = ctoken
	}
}

func (s *devOpsScanner) listBuilds(organization string, project string) {
	buildsCount := 0
	continuationToken := ""
	for {
		builds, _, ctoken, err := s.options.Client.ListBuilds(continuationToken, organization, project)
		if err != nil {
			log.Error().Err(err).Str("organization", organization).Str("project", project).Msg("Failed fetching builds")
		}

		for _, build := range builds {
			log.Debug().Str("url", build.Links.Web.Href).Msg("Build")
			s.listLogs(organization, project, build.ID, build.Links.Web.Href)

			if s.options.Artifacts {
				s.listArtifacts(organization, project, build.ID, build.Links.Web.Href)
			}

			buildsCount = buildsCount + 1
			if buildsCount >= s.options.MaxBuilds && s.options.MaxBuilds > 0 {
				log.Trace().Str("organization", organization).Str("project", project).Msg("Reached MaxBuild runs, skip remaining")
				return
			}
		}

		if ctoken == "" {
			break
		}
		continuationToken = ctoken
	}
}

func (s *devOpsScanner) listLogs(organization string, project string, buildId int, buildWebUrl string) {
	logs, _, err := s.options.Client.ListBuildLogs(organization, project, buildId)
	if err != nil {
		log.Error().Err(err).Str("organization", organization).Str("project", project).Int("build", buildId).Msg("Failed fetching build logs")
	}

	for _, logEntry := range logs {
		log.Trace().Str("url", logEntry.URL).Msg("Download log")
		logLines, _, err := s.options.Client.GetLog(organization, project, buildId, logEntry.ID)
		if err != nil {
			log.Error().Err(err).Str("organization", organization).Str("project", project).Int("build", buildId).Int("logId", logEntry.ID).Msg("Failed fetching build log lines")
		}

		s.scanLogLines(logLines, buildWebUrl)
	}
}

func (s *devOpsScanner) scanLogLines(logs []byte, buildWebUrl string) {
	logResult, err := logline.ProcessLogs(logs, logline.ProcessOptions{
		MaxGoRoutines:     s.options.MaxScanGoRoutines,
		VerifyCredentials: s.options.SecretsVerification,
		HitTimeout:        s.options.HitTimeout,
	})
	if err != nil {
		log.Debug().Err(err).Str("build", buildWebUrl).Msg("Failed detecting secrets of a single log line")
		return
	}

	result.ReportFindings(logResult.Findings, result.ReportOptions{
		LocationURL: buildWebUrl,
	})
}

func (s *devOpsScanner) listArtifacts(organization string, project string, buildId int, buildWebUrl string) {
	continuationToken := ""
	for {
		artifacts, _, ctoken, err := s.options.Client.ListBuildArtifacts(continuationToken, organization, project, buildId)
		if err != nil {
			log.Error().Err(err).Str("organization", organization).Str("project", project).Int("build", buildId).Msg("Failed fetching build artifacts")
		}

		for _, artifact := range artifacts {
			log.Trace().Str("name", artifact.Name).Msg("Analyze artifact")
			s.analyzeArtifact(artifact, buildWebUrl)
		}

		if ctoken == "" {
			break
		}
		continuationToken = ctoken
	}
}

func (s *devOpsScanner) analyzeArtifact(art Artifact, buildWebUrl string) {
	artifactSize, err := strconv.ParseInt(art.Resource.Properties.Artifactsize, 10, 64)
	if err == nil && artifactSize > s.options.MaxArtifactSize {
		log.Debug().
			Int64("bytes", artifactSize).
			Int64("maxBytes", s.options.MaxArtifactSize).
			Str("name", art.Name).
			Str("url", buildWebUrl).
			Msg("Skipped large artifact")
		return
	}

	zipBytes, _, err := s.options.Client.DownloadArtifactZip(art.Resource.DownloadURL)
	if err != nil {
		log.Err(err).Msg("Failed downloading artifact")
		return
	}

	_, err = artifactproc.ProcessZipArtifact(zipBytes, artifactproc.ProcessOptions{
		MaxGoRoutines:     s.options.MaxScanGoRoutines,
		VerifyCredentials: s.options.SecretsVerification,
		BuildURL:          buildWebUrl,
		ArtifactName:      art.Name,
		HitTimeout:        s.options.HitTimeout,
	})
	if err != nil {
		log.Err(err).Msg("Failed processing artifact")
		return
	}
}

// InitializeOptions prepares scan options from CLI parameters.
func InitializeOptions(username, accessToken, devOpsURL, organization, project, maxArtifactSizeStr string,
	artifacts, secretsVerification bool,
	maxBuilds, maxScanGoRoutines int, confidenceFilter []string, hitTimeout time.Duration) (ScanOptions, error) {

	byteSize, err := format.ParseHumanSize(maxArtifactSizeStr)
	if err != nil {
		return ScanOptions{}, err
	}

	ctx := context.Background()
	client := NewClient(username, accessToken, devOpsURL)

	return ScanOptions{
		Username:            username,
		AccessToken:         accessToken,
		ConfidenceFilter:    confidenceFilter,
		MaxScanGoRoutines:   maxScanGoRoutines,
		SecretsVerification: secretsVerification,
		MaxBuilds:           maxBuilds,
		Organization:        organization,
		Project:             project,
		Artifacts:           artifacts,
		DevOpsURL:           devOpsURL,
		MaxArtifactSize:     byteSize,
		HitTimeout:          hitTimeout,
		Context:             ctx,
		Client:              client,
	}, nil
}
