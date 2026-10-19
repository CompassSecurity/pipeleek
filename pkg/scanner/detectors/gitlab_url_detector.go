package detectors

import (
	"context"
	"sync"

	"github.com/CompassSecurity/pipeleek/pkg/gitlab/util"
	"github.com/CompassSecurity/pipeleek/pkg/scanner/rules"
	"github.com/acarl005/stripansi"
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
	pattern  rules.CompiledPattern
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
	strategies := map[string]verificationStrategy{
		"Gitlab - Personal Access Token v2":    verifyUserAPI,
		"Gitlab - Personal Access Token v3":    verifyUserAPI,
		"Gitlab - SCIM/OAuth Access Token":     verifyUserAPI,
		"Gitlab - Runner Authentication Token": verifyRunnerAPI,
		"Gitlab - Runner Token (Legacy)":       verifyRunnerAPI,
		"Gitlab - Pipeline Trigger Token":      verifyNone,
		"Gitlab - Runner Registration Token":   verifyNone,
		"Gitlab - Deploy Token":                verifyNone,
		"Gitlab - CI Build Token":              verifyNone,
		"Gitlab - OAuth Application Secret":    verifyNone,
		"Gitlab - Feed Token":                  verifyNone,
		"Gitlab - Incoming Mail Token":         verifyNone,
		"Gitlab - Feature Flags Client Token":  verifyNone,
		"Gitlab - Agent for Kubernetes Token":  verifyNone,
	}
	var patterns []gitlabPattern
	for _, pattern := range rules.BuiltinPatterns() {
		name := pattern.Pattern.Pattern.Name
		if strategy, ok := strategies[name]; ok {
			patterns = append(patterns, gitlabPattern{name: name, pattern: pattern, strategy: strategy})
			delete(strategies, name)
		}
	}
	if len(strategies) != 0 {
		log.Fatal().Msg("Missing built-in GitLab token definitions")
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
	return d.FromDataWithURL(ctx, verify, data, GetGitLabURL())
}

// FromDataWithURL verifies matches against url instead of the package-global URL.
func (d *GitLabURLDetector) FromDataWithURL(ctx context.Context, verify bool, data []byte, url string) ([]detectors.Result, error) {
	data = []byte(stripansi.Strip(string(data)))
	var results []detectors.Result

	for _, pattern := range d.patterns {
		if err := ctx.Err(); err != nil {
			return results, err
		}

		matches := pattern.pattern.FindAllIndex(data)
		seenMatches := make(map[string]struct{}, len(matches))
		for _, index := range matches {
			if err := ctx.Err(); err != nil {
				return results, err
			}

			matchBytes := data[index[0]:index[1]]
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
