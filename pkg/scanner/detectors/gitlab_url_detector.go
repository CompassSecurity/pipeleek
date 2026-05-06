package detectors

import (
	"context"
	"regexp"
	"sync"

	"github.com/CompassSecurity/pipeleek/pkg/gitlab/util"
	"github.com/rs/zerolog/log"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

var (
	gitlabURLMutex sync.RWMutex
	gitlabURL      string
)

type gitlabPattern struct {
	name     string
	regex    *regexp.Regexp
	strategy verificationStrategy
}

type verificationStrategy uint8

const (
	verifyNone verificationStrategy = iota
	verifyUserAPI
	verifyRunnerAPI
)

func SetGitLabURL(url string) {
	gitlabURLMutex.Lock()
	defer gitlabURLMutex.Unlock()
	gitlabURL = url
}

func GetGitLabURL() string {
	gitlabURLMutex.RLock()
	defer gitlabURLMutex.RUnlock()
	return gitlabURL
}

func ClearGitLabURL() {
	gitlabURLMutex.Lock()
	defer gitlabURLMutex.Unlock()
	gitlabURL = ""
}

type GitLabURLDetector struct {
	patterns []gitlabPattern
}

func NewGitLabURLDetector() (*GitLabURLDetector, error) {
	patterns := []gitlabPattern{
		{name: "Gitlab - Personal Access Token v2", regex: regexp.MustCompile(`glpat-[a-zA-Z0-9\-=_]{20,22}`), strategy: verifyUserAPI},
		{name: "Gitlab - Personal Access Token v3", regex: regexp.MustCompile(`\b(glpat-[a-zA-Z0-9\-=_]{27,300}.[0-9a-z]{2}.[a-z0-9]{9})\b`), strategy: verifyUserAPI},
		{name: "Gitlab - Pipeline Trigger Token", regex: regexp.MustCompile(`glptt-[a-zA-Z0-9\-=_]{20,}`), strategy: verifyNone},
		{name: "Gitlab - Runner Authentication Token", regex: regexp.MustCompile(`glrt-[a-zA-Z0-9\-=_]{20,}`), strategy: verifyRunnerAPI},
		{name: "Gitlab - Runner Registration Token", regex: regexp.MustCompile(`glrtr-[a-zA-Z0-9\-=_]{20,}`), strategy: verifyNone},
		{name: "Gitlab - Deploy Token", regex: regexp.MustCompile(`gldt-[a-zA-Z0-9\-=_]{20,}`), strategy: verifyNone},
		{name: "Gitlab - CI Build Token", regex: regexp.MustCompile(`glcbt-[a-zA-Z0-9\-=_]{20,}`), strategy: verifyNone},
		{name: "Gitlab - OAuth Application Secret", regex: regexp.MustCompile(`gloas-[a-zA-Z0-9\-=_]{20,}`), strategy: verifyNone},
		{name: "Gitlab - SCIM/OAuth Access Token", regex: regexp.MustCompile(`glsoat-[a-zA-Z0-9\-=_]{20,}`), strategy: verifyUserAPI},
		{name: "Gitlab - Feed Token", regex: regexp.MustCompile(`glft-[a-zA-Z0-9\-=_]{20,}`), strategy: verifyNone},
		{name: "Gitlab - Incoming Mail Token", regex: regexp.MustCompile(`glimt-[a-zA-Z0-9\-=_]{20,}`), strategy: verifyNone},
		{name: "Gitlab - Feature Flags Client Token", regex: regexp.MustCompile(`glffct-[a-zA-Z0-9\-=_]{20,}`), strategy: verifyNone},
		{name: "Gitlab - Agent for Kubernetes Token", regex: regexp.MustCompile(`glagent-[a-zA-Z0-9\-=_]{20,}`), strategy: verifyNone},
		{name: "Gitlab - Runner Token (Legacy)", regex: regexp.MustCompile(`GR1348941[a-zA-Z0-9\-=_]{20,}`), strategy: verifyRunnerAPI},
	}

	return &GitLabURLDetector{patterns: patterns}, nil
}

func (d *GitLabURLDetector) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	var results []detectors.Result

	dataStr := string(data)
	url := GetGitLabURL()

	for _, pattern := range d.patterns {
		matches := pattern.regex.FindAllString(dataStr, -1)
		for _, match := range matches {
			result := detectors.Result{
				DetectorName: pattern.name,
				Raw:          []byte(match),
				Verified:     false,
			}

			if verify && url != "" && pattern.strategy != verifyNone {
				if d.verifyTokenAgainstURL(match, url, pattern.name, pattern.strategy) {
					result.Verified = true
					result.VerificationFromCache = false
				} else {
					// If URL verification fails for an API-capable token, skip this result
					// during verification-enabled mode
					continue
				}
			}

			results = append(results, result)
		}
	}

	return results, nil
}

func (d *GitLabURLDetector) verifyTokenAgainstURL(token string, gitlabURL string, tokenName string, strategy verificationStrategy) bool {
	client, err := util.GetGitlabClient(token, gitlabURL)
	if err != nil {
		log.Debug().Err(err).Str("url", gitlabURL).Str("token_type", tokenName).Msg("Failed to create GitLab client for token verification")
		return false
	}

	switch strategy {
	case verifyUserAPI:
		_, _, err = client.Users.CurrentUser()
	case verifyRunnerAPI:
		_, err = client.Runners.VerifyRegisteredRunner(&gitlab.VerifyRegisteredRunnerOptions{Token: gitlab.Ptr(token)})
	default:
		return false
	}
	if err != nil {
		log.Debug().Err(err).Str("url", gitlabURL).Str("token_type", tokenName).Msg("Token verification failed against GitLab instance")
		return false
	}

	log.Debug().Str("url", gitlabURL).Str("token_type", tokenName).Msg("Token verified successfully against GitLab instance")
	return true
}

func (d *GitLabURLDetector) Keywords() []string {
	return []string{
		"glpat-",
		"glptt-",
		"gldt-",
		"glrt-",
		"glrtr-",
		"glcbt-",
		"gloas-",
		"glsoat-",
		"glft-",
		"glimt-",
		"glffct-",
		"glagent-",
		"GR1348941",
	}
}

func (d *GitLabURLDetector) Type() string {
	return "GitLab"
}

func (d *GitLabURLDetector) Description() string {
	return "GitLab Token Detector with Self-Hosted Instance Verification"
}
