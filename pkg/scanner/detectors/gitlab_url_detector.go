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
	detectorOnce   sync.Once
	detector       *GitLabURLDetector
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
	patterns          []gitlabPattern
	verificationCache sync.Map
}

func NewGitLabURLDetector() *GitLabURLDetector {
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

	return &GitLabURLDetector{patterns: patterns}
}

func GetGitLabURLDetector() *GitLabURLDetector {
	detectorOnce.Do(func() {
		detector = NewGitLabURLDetector()
	})
	return detector
}

func (d *GitLabURLDetector) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	var results []detectors.Result
	url := GetGitLabURL()

	for _, pattern := range d.patterns {
		if err := ctx.Err(); err != nil {
			return results, err
		}

		matches := pattern.regex.FindAll(data, -1)
		seenMatches := make(map[string]struct{}, len(matches))
		for _, matchBytes := range matches {
			if err := ctx.Err(); err != nil {
				return results, err
			}

			match := string(matchBytes)
			if _, seen := seenMatches[match]; seen {
				continue
			}
			seenMatches[match] = struct{}{}

			result := detectors.Result{
				DetectorName: pattern.name,
				Raw:          append([]byte(nil), matchBytes...),
				Verified:     false,
			}

			if verify && url != "" && pattern.strategy != verifyNone {
				if d.verifyTokenAgainstURL(ctx, match, url, pattern.name, pattern.strategy) {
					result.Verified = true
				} else {
					continue
				}
			}

			results = append(results, result)
		}
	}

	return results, nil
}

func (d *GitLabURLDetector) verifyTokenAgainstURL(ctx context.Context, token string, gitlabURL string, tokenName string, strategy verificationStrategy) bool {
	if err := ctx.Err(); err != nil {
		return false
	}

	cacheKey := string(rune(strategy)) + "|" + gitlabURL + "|" + token
	if cached, ok := d.verificationCache.Load(cacheKey); ok {
		return cached.(bool)
	}

	client, err := util.GetGitlabClient(token, gitlabURL)
	if err != nil {
		log.Debug().Err(err).Str("url", gitlabURL).Str("token_type", tokenName).Msg("Failed to create GitLab client for token verification")
		d.verificationCache.Store(cacheKey, false)
		return false
	}

	switch strategy {
	case verifyUserAPI:
		_, _, err = client.Users.CurrentUser(gitlab.WithContext(ctx))
	case verifyRunnerAPI:
		_, err = client.Runners.VerifyRegisteredRunner(&gitlab.VerifyRegisteredRunnerOptions{Token: gitlab.Ptr(token)}, gitlab.WithContext(ctx))
	default:
		d.verificationCache.Store(cacheKey, false)
		return false
	}
	if err != nil {
		log.Debug().Err(err).Str("url", gitlabURL).Str("token_type", tokenName).Msg("Token verification failed against GitLab instance")
		d.verificationCache.Store(cacheKey, false)
		return false
	}

	log.Debug().Str("url", gitlabURL).Str("token_type", tokenName).Msg("Token verified successfully against GitLab instance")
	d.verificationCache.Store(cacheKey, true)
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
