package detectors

import (
	"context"
	"regexp"
	"sync"

	"github.com/CompassSecurity/pipeleek/pkg/gitlab/util"
	"github.com/rs/zerolog/log"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

var (
	gitlabURLMutex sync.RWMutex
	gitlabURL      string
)

type gitlabPattern struct {
	name       string
	regex      *regexp.Regexp
	verifiable bool
}

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
		{name: "Gitlab - Personal Access Token v2", regex: regexp.MustCompile(`glpat-[a-zA-Z0-9\-=_]{20,22}`), verifiable: true},
		{name: "Gitlab - Personal Access Token v3", regex: regexp.MustCompile(`\b(glpat-[a-zA-Z0-9\-=_]{27,300}.[0-9a-z]{2}.[a-z0-9]{9})\b`), verifiable: true},
		{name: "Gitlab - Pipeline Trigger Token", regex: regexp.MustCompile(`glptt-[a-zA-Z0-9\-=_]{20,}`), verifiable: false},
		{name: "Gitlab - Runner Authentication Token", regex: regexp.MustCompile(`glrt-[a-zA-Z0-9\-=_]{20,}`), verifiable: false},
		{name: "Gitlab - Runner Registration Token", regex: regexp.MustCompile(`glrtr-[a-zA-Z0-9\-=_]{20,}`), verifiable: false},
		{name: "Gitlab - Deploy Token", regex: regexp.MustCompile(`gldt-[a-zA-Z0-9\-=_]{20,}`), verifiable: false},
		{name: "Gitlab - CI Build Token", regex: regexp.MustCompile(`glcbt-[a-zA-Z0-9\-=_]{20,}`), verifiable: false},
		{name: "Gitlab - OAuth Application Secret", regex: regexp.MustCompile(`gloas-[a-zA-Z0-9\-=_]{20,}`), verifiable: false},
		{name: "Gitlab - SCIM/OAuth Access Token", regex: regexp.MustCompile(`glsoat-[a-zA-Z0-9\-=_]{20,}`), verifiable: true},
		{name: "Gitlab - Feed Token", regex: regexp.MustCompile(`glft-[a-zA-Z0-9\-=_]{20,}`), verifiable: false},
		{name: "Gitlab - Incoming Mail Token", regex: regexp.MustCompile(`glimt-[a-zA-Z0-9\-=_]{20,}`), verifiable: false},
		{name: "Gitlab - Feature Flags Client Token", regex: regexp.MustCompile(`glffct-[a-zA-Z0-9\-=_]{20,}`), verifiable: false},
		{name: "Gitlab - Agent for Kubernetes Token", regex: regexp.MustCompile(`glagent-[a-zA-Z0-9\-=_]{20,}`), verifiable: false},
		{name: "Gitlab - Runner Token (Legacy)", regex: regexp.MustCompile(`GR1348941[a-zA-Z0-9\-=_]{20,}`), verifiable: false},
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

			// Verify only token types that can authenticate against GitLab API.
			if verify && url != "" && pattern.verifiable {
				if d.verifyTokenAgainstURL(match, url, pattern.name) {
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

func (d *GitLabURLDetector) verifyTokenAgainstURL(token string, gitlabURL string, tokenName string) bool {
	client, err := util.GetGitlabClient(token, gitlabURL)
	if err != nil {
		log.Debug().Err(err).Str("url", gitlabURL).Str("token_type", tokenName).Msg("Failed to create GitLab client for token verification")
		return false
	}

	_, _, err = client.Users.CurrentUser()
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
