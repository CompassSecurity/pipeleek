package scan

import (
	"net/url"
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/format"
	"github.com/CompassSecurity/pipeleek/pkg/gitlab/util"
	"github.com/CompassSecurity/pipeleek/pkg/scanner"
	"github.com/rs/zerolog/log"
)

type Scanner interface {
	scanner.BaseScanner
	GetQueueStatus() int
}

type gitlabScanner struct {
	options *ScanOptions
}

var _ scanner.BaseScanner = (*gitlabScanner)(nil)

func NewScanner(opts *ScanOptions) Scanner {
	return &gitlabScanner{
		options: opts,
	}
}

// Scan performs the GitLab scanning operation.
func (s *gitlabScanner) Scan() error {
	if !isUnauthenticatedMode(s.options) {
		version := util.DetermineVersion(s.options.GitlabUrl, s.options.GitlabApiToken)
		log.Info().Str("version", version.Version).Str("revision", version.Revision).Msg("Gitlab Version Check")
	}

	ScanGitLabPipelines(s.options)
	log.Info().Msg("Scan Finished, Bye Bye 🏳️‍🌈🔥")
	return nil
}

// GetQueueStatus returns the current queue status.
func (s *gitlabScanner) GetQueueStatus() int {
	return GetQueueStatus()
}

// InitializeOptions prepares scan options from CLI parameters.
func InitializeOptions(gitlabUrl, gitlabApiToken, gitlabCookie, projectSearchQuery, repository, namespace, queueFolder, maxArtifactSizeStr string,
	artifacts, owned, member, truffleHogVerification bool,
	jobLimit, maxScanGoRoutines int, confidenceFilter []string, hitTimeout time.Duration) (*ScanOptions, error) {

	_, err := url.ParseRequestURI(gitlabUrl)
	if err != nil {
		return nil, err
	}

	byteSize, err := format.ParseHumanSize(maxArtifactSizeStr)
	if err != nil {
		return nil, err
	}

	return &ScanOptions{
		GitlabUrl:              gitlabUrl,
		GitlabApiToken:         gitlabApiToken,
		GitlabCookie:           gitlabCookie,
		ProjectSearchQuery:     projectSearchQuery,
		Artifacts:              artifacts,
		Owned:                  owned,
		Member:                 member,
		Repository:             repository,
		Namespace:              namespace,
		JobLimit:               jobLimit,
		ConfidenceFilter:       confidenceFilter,
		MaxArtifactSize:        byteSize,
		MaxScanGoRoutines:      maxScanGoRoutines,
		QueueFolder:            queueFolder,
		TruffleHogVerification: truffleHogVerification,
		HitTimeout:             hitTimeout,
	}, nil
}
