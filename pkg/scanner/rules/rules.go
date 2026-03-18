package rules

import (
	"errors"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/CompassSecurity/pipeleek/pkg/httpclient"
	"github.com/CompassSecurity/pipeleek/pkg/scanner/types"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/rs/zerolog/log"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
	"gopkg.in/yaml.v3"
)

var ruleFile = "https://raw.githubusercontent.com/mazen160/secrets-patterns-db/master/db/rules-stable.yml"
var ruleFileName = "rules.yml"

var secretsPatterns = types.SecretsPatterns{}
var truffelhogRules []detectors.Detector

func DownloadRules() {
	if _, err := os.Stat(ruleFileName); errors.Is(err, os.ErrNotExist) {
		log.Debug().Msg("No rules file found, downloading")
		err := downloadFile(ruleFile, ruleFileName, httpclient.GetPipeleekHTTPClient("", nil, nil))
		if err != nil {
			log.Fatal().Stack().Err(err).Msg("Failed downloading rules file")
			os.Exit(1)
		}
	}
}

func downloadFile(url string, filepath string, client *retryablehttp.Client) error {
	// #nosec G304 - Creating file for rules download at controlled internal temp path
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}

	return nil
}

func InitRules(confidenceFilter []string) {
	DownloadRules()

	if len(secretsPatterns.Patterns) == 0 {
		log.Debug().Msg("Loading rules.yml from filesystem")
		yamlFile, err := os.ReadFile(ruleFileName)
		if err != nil {
			log.Fatal().Stack().Err(err).Msg("Failed opening rules file")
		}
		err = yaml.Unmarshal(yamlFile, &secretsPatterns)
		if err != nil {
			log.Fatal().Stack().Err(err).Msg("Failed unmarshalling rules file")
		}

		patterns := AppendPipeleekRules(secretsPatterns.Patterns)

		if len(confidenceFilter) > 0 {
			log.Debug().Str("filter", strings.Join(confidenceFilter, ",")).Msg("Applying confidence filter")
			filterdPatterns := []types.PatternElement{}
			for _, pattern := range patterns {
				if slices.Contains(confidenceFilter, pattern.Pattern.Confidence) {
					filterdPatterns = append(filterdPatterns, pattern)
				}
			}
			secretsPatterns.Patterns = filterdPatterns

			totalRules := len(secretsPatterns.Patterns)
			if totalRules == 0 {
				log.Info().Int("count", totalRules).Msg("Your confidence filter removed all rules, are you sure? TruffleHog Rules will still detect secrets. This equals --confidence high-verified")
			}

			log.Debug().Int("count", totalRules).Msg("Loaded filtered rules")
		} else {
			secretsPatterns.Patterns = patterns
			log.Debug().Int("count", len(secretsPatterns.Patterns)).Msg("Loaded rules.yml rules")
		}
	}

	truffelhogRules = defaults.DefaultDetectors()
	if len(truffelhogRules) < 1 {
		log.Fatal().Msg("No trufflehog rules have been loaded, this is a bug")
	} else {
		log.Debug().Int("count", len(truffelhogRules)).Msg("Loaded TruffleHog rules")
	}
}

func AppendPipeleekRules(rules []types.PatternElement) []types.PatternElement {
	customRules := []types.PatternElement{}
	customRules = append(customRules, types.PatternElement{Pattern: types.PatternPattern{Name: "Gitlab - Predefined Environment Variable", Regex: `(GITLAB_USER_ID|KUBECONFIG|CI_SERVER_TLS_KEY_FILE|CI_REPOSITORY_URL|CI_REGISTRY_PASSWORD|DOCKER_AUTH_CONFIG)=.*`, Confidence: "medium"}})

	// Built-in rules for GitLab token types to ensure detection regardless of
	// TruffleHog verification (which only verifies against gitlab.com and
	// therefore misses tokens for self-hosted GitLab instances).
	customRules = append(customRules,
		// https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/gitlab/v2/gitlab_v2.go
		types.PatternElement{Pattern: types.PatternPattern{Name: "Gitlab - Personal Access Token v2", Regex: `glpat-[a-zA-Z0-9\-=_]{20,22}`, Confidence: "high"}},
		// https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/gitlab/v3/gitlab_v3.go
		types.PatternElement{Pattern: types.PatternPattern{Name: "Gitlab - Personal Access Token v3", Regex: `glpat-[a-zA-Z0-9\-=_]{27,300}.[0-9a-z]{2}.[a-z0-9]{9}`, Confidence: "high"}},
		// https://github.com/gitlabhq/gitlabhq/blob/master/app/models/ci/trigger.rb
		types.PatternElement{Pattern: types.PatternPattern{Name: "Gitlab - Pipeline Trigger Token", Regex: `glptt-[a-zA-Z0-9\-=_]{20,}`, Confidence: "high"}},
		// https://github.com/gitlabhq/gitlabhq/blob/master/app/models/ci/runner.rb (CREATED_RUNNER_TOKEN_PREFIX)
		types.PatternElement{Pattern: types.PatternPattern{Name: "Gitlab - Runner Authentication Token", Regex: `glrt-[a-zA-Z0-9\-=_]{20,}`, Confidence: "high"}},
		// https://github.com/gitlabhq/gitlabhq/blob/master/app/models/ci/runner.rb (REGISTRATION_RUNNER_TOKEN_PREFIX)
		types.PatternElement{Pattern: types.PatternPattern{Name: "Gitlab - Runner Registration Token", Regex: `glrtr-[a-zA-Z0-9\-=_]{20,}`, Confidence: "high"}},
		// https://github.com/gitlabhq/gitlabhq/blob/master/app/models/deploy_token.rb
		types.PatternElement{Pattern: types.PatternPattern{Name: "Gitlab - Deploy Token", Regex: `gldt-[a-zA-Z0-9\-=_]{20,}`, Confidence: "high"}},
		// https://github.com/gitlabhq/gitlabhq/blob/master/app/models/ci/build.rb
		types.PatternElement{Pattern: types.PatternPattern{Name: "Gitlab - CI Build Token", Regex: `glcbt-[a-zA-Z0-9\-=_]{20,}`, Confidence: "high"}},
		// https://github.com/gitlabhq/gitlabhq/blob/master/spec/lib/authn/tokens/oauth_application_secret_spec.rb
		types.PatternElement{Pattern: types.PatternPattern{Name: "Gitlab - OAuth Application Secret", Regex: `gloas-[a-zA-Z0-9\-=_]{20,}`, Confidence: "high"}},
		// https://docs.gitlab.com/security/token_overview/
		types.PatternElement{Pattern: types.PatternPattern{Name: "Gitlab - SCIM/OAuth Access Token", Regex: `glsoat-[a-zA-Z0-9\-=_]{20,}`, Confidence: "high"}},
		// https://docs.gitlab.com/security/token_overview/
		types.PatternElement{Pattern: types.PatternPattern{Name: "Gitlab - Feed Token", Regex: `glft-[a-zA-Z0-9\-=_]{20,}`, Confidence: "high"}},
		// https://docs.gitlab.com/security/token_overview/
		types.PatternElement{Pattern: types.PatternPattern{Name: "Gitlab - Incoming Mail Token", Regex: `glimt-[a-zA-Z0-9\-=_]{20,}`, Confidence: "high"}},
		// https://docs.gitlab.com/security/token_overview/
		types.PatternElement{Pattern: types.PatternPattern{Name: "Gitlab - Feature Flags Client Token", Regex: `glffct-[a-zA-Z0-9\-=_]{20,}`, Confidence: "high"}},
		// https://docs.gitlab.com/security/token_overview/
		types.PatternElement{Pattern: types.PatternPattern{Name: "Gitlab - Agent for Kubernetes Token", Regex: `glagent-[a-zA-Z0-9\-=_]{20,}`, Confidence: "high"}},
		// https://github.com/gitlabhq/gitlabhq/blob/master/app/models/concerns/runners_token_prefixable.rb
		types.PatternElement{Pattern: types.PatternPattern{Name: "Gitlab - Runner Token (Legacy)", Regex: `GR1348941[a-zA-Z0-9\-=_]{20,}`, Confidence: "high"}},
	)

	return slices.Concat(rules, customRules)
}

func GetSecretsPatterns() types.SecretsPatterns {
	return secretsPatterns
}

func GetTruffleHogRules() []detectors.Detector {
	return truffelhogRules
}
