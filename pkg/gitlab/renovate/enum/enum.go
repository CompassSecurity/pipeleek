package renovate

import (
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/CompassSecurity/pipeleek/pkg/format"
	"github.com/CompassSecurity/pipeleek/pkg/gitlab/util"
	"github.com/CompassSecurity/pipeleek/pkg/httpclient"
	renovateutil "github.com/CompassSecurity/pipeleek/pkg/renovate"
	"github.com/rs/zerolog/log"
	"github.com/yosuke-furukawa/json5/encoding/json5"

	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// EnumOptions contains all options for the renovate enum command
type EnumOptions struct {
	GitlabUrl                   string
	GitlabApiToken              string
	Owned                       bool
	Member                      bool
	ProjectSearchQuery          string
	Fast                        bool
	Dump                        bool
	SelfHostedOptions           []string
	Page                        int
	Repository                  string
	Namespace                   string
	OrderBy                     string
	ExtendRenovateConfigService string
	MinAccessLevel              int
}

// RunEnumerate performs the renovate enumeration with the given options
func RunEnumerate(opts EnumOptions) {
	git, err := util.GetGitlabClient(opts.GitlabApiToken, opts.GitlabUrl)
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Failed creating gitlab client")
	}

	if opts.ExtendRenovateConfigService != "" {
		err := validateRenovateConfigService(opts.ExtendRenovateConfigService)
		if err != nil {
			log.Fatal().Stack().Err(err).Msg("Invalid extendRenovateConfigService URL")
		}
		log.Info().Str("service", opts.ExtendRenovateConfigService).Msg("Using renovate config extension service")
	}

	validateOrderBy(opts.OrderBy)

	if opts.Repository != "" {
		scanSingleProject(git, opts.Repository, opts)
	} else if opts.Namespace != "" {
		scanNamespace(git, opts.Namespace, opts)
	} else {
		fetchProjects(git, opts)
	}

	log.Info().Msg("Done, Bye Bye 🏳️‍🌈🔥")
}

func scanSingleProject(git *gitlab.Client, projectName string, opts EnumOptions) {
	log.Info().Str("repository", projectName).Msg("Scanning specific repository for Renovate configuration")
	project, resp, err := git.Projects.GetProject(projectName, &gitlab.GetProjectOptions{})
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Failed fetching project by repository name")
	}
	if resp.StatusCode == 404 {
		log.Fatal().Msg("Project not found")
	}
	identifyRenovateBotJob(git, project, opts)
}

func scanNamespace(git *gitlab.Client, namespace string, opts EnumOptions) {
	log.Info().Str("namespace", namespace).Msg("Scanning specific namespace for Renovate configuration")
	group, _, err := git.Groups.GetGroup(namespace, &gitlab.GetGroupOptions{})
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Failed fetching namespace")
	}

	projectOpts := &gitlab.ListGroupProjectsOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: 100,
			Page:    int64(opts.Page),
		},
		OrderBy:          gitlab.Ptr(opts.OrderBy),
		Owned:            gitlab.Ptr(opts.Owned),
		Search:           gitlab.Ptr(opts.ProjectSearchQuery),
		WithShared:       gitlab.Ptr(true),
		IncludeSubGroups: gitlab.Ptr(true),
	}

	err = util.IterateGroupProjects(git, group.ID, projectOpts, func(project *gitlab.Project) error {
		log.Debug().Str("url", project.WebURL).Msg("Check project")
		identifyRenovateBotJob(git, project, opts)
		return nil
	})
	if err != nil {
		log.Error().Stack().Err(err).Msg("Failed iterating group projects")
		return
	}

	log.Info().Msg("Fetched all namespace projects")
}

func fetchProjects(git *gitlab.Client, opts EnumOptions) {
	log.Info().Msg("Fetching projects")

	projectOpts := &gitlab.ListProjectsOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: 100,
			Page:    int64(opts.Page),
		},
		OrderBy:    gitlab.Ptr(opts.OrderBy),
		Owned:      gitlab.Ptr(opts.Owned),
		Membership: gitlab.Ptr(opts.Member),
		Search:     gitlab.Ptr(opts.ProjectSearchQuery),
	}

	err := util.IterateProjects(git, projectOpts, func(project *gitlab.Project) error {
		log.Debug().Str("url", project.WebURL).Msg("Check project")
		identifyRenovateBotJob(git, project, opts)
		return nil
	})
	if err != nil {
		log.Error().Stack().Err(err).Msg("Failed iterating projects")
		return
	}

	log.Info().Msg("Fetched all projects")
}

func identifyRenovateBotJob(git *gitlab.Client, project *gitlab.Project, opts EnumOptions) {
	ciCdYml, err := util.FetchCICDYml(git, project.ID)
	if err != nil {
		// silently skip
		return
	}

	hasCiCdRenovateConfig := detectCiCdConfig(ciCdYml)
	var configFile *gitlab.File = nil
	var configFileContent string
	if !opts.Fast {
		configFile, configFileContent = detectRenovateConfigFile(git, project)

		if opts.ExtendRenovateConfigService != "" {
			// Replace any occurrence of "local>" with "gitlab>" this best effort
			configFileContent = strings.ReplaceAll(configFileContent, "local>", "gitlab>")
			configFileContent = extendRenovateConfig(configFileContent, project, opts)
		}
	}

	if hasCiCdRenovateConfig || configFile != nil {
		if opts.Dump {
			filename := ""
			if configFile != nil {
				filename = configFile.FileName
			}
			dumpConfigFileContents(project, ciCdYml, configFileContent, filename)
		}

		selfHostedConfigFile := false
		if configFile != nil {
			selfHostedConfigFile = isSelfHostedConfig(configFileContent, opts)
		}

		autodiscovery := detectAutodiscovery(ciCdYml, configFileContent)
		filterType := ""
		filterValue := ""
		hasAutodiscoveryFilters := false
		if autodiscovery {
			hasAutodiscoveryFilters, filterType, filterValue = detectAutodiscoveryFilters(ciCdYml, configFileContent)
		}

		log.Warn().
			Str("pipelines", string(project.BuildsAccessLevel)).
			Bool("hasAutodiscovery", autodiscovery).
			Bool("hasAutodiscoveryFilters", hasAutodiscoveryFilters).
			Str("autodiscoveryFilterType", filterType).
			Str("autodiscoveryFilterValue", filterValue).
			Bool("hasConfigFile", configFile != nil).
			Bool("selfHostedConfigFile", selfHostedConfigFile).
			Str("url", project.WebURL).
			Msg("Identified Renovate (bot) configuration")

		if hasCiCdRenovateConfig {
			yml, err := format.PrettyPrintYAML(ciCdYml)
			if err != nil {
				log.Error().Stack().Err(err).Msg("Failed pretty printing project CI/CD YML")
				return
			}
			log.Debug().Msg(format.GetPlatformAgnosticNewline() + yml)
		}
	}
}

func detectCiCdConfig(cicdConf string) bool {
	// Check for common Renovate bot job identifiers in CI/CD configuration
	return format.ContainsI(cicdConf, "renovate/renovate") ||
		format.ContainsI(cicdConf, "renovatebot/renovate") ||
		format.ContainsI(cicdConf, "renovate-bot/renovate-runner") ||
		format.ContainsI(cicdConf, "RENOVATE_") ||
		format.ContainsI(cicdConf, "npx renovate")
}

func detectAutodiscovery(cicdConf string, configFileContent string) bool {
	// Check for autodiscover flag: https://docs.renovatebot.com/self-hosted-configuration/#autodiscover
	hasAutodiscoveryInConfigFile := format.ContainsI(configFileContent, "autodiscover")

	hasAutodiscoveryinCiCD := (format.ContainsI(cicdConf, "--autodiscover") || format.ContainsI(cicdConf, "RENOVATE_AUTODISCOVER")) &&
		(!format.ContainsI(cicdConf, "--autodiscover=false") && !format.ContainsI(cicdConf, "--autodiscover false") && !format.ContainsI(cicdConf, "RENOVATE_AUTODISCOVER: false") && !format.ContainsI(cicdConf, "RENOVATE_AUTODISCOVER=false"))

	return hasAutodiscoveryInConfigFile || hasAutodiscoveryinCiCD
}

func detectAutodiscoveryFilters(cicdConf, configFileContent string) (bool, string, string) {
	type groupDef struct {
		name string
		keys []string
	}

	groups := []groupDef{
		{"autodiscoverFilter", []string{"autodiscoverFilter", "RENOVATE_AUTODISCOVER_FILTER", "--autodiscover-filter"}},
		{"autodiscoverNamespaces", []string{"autodiscoverNamespaces", "RENOVATE_AUTODISCOVER_NAMESPACES", "--autodiscover-namespaces"}},
		{"autodiscoverProjects", []string{"autodiscoverProjects", "RENOVATE_AUTODISCOVER_PROJECTS", "--autodiscover-projects"}},
		{"autodiscoverTopics", []string{"autodiscoverTopics", "RENOVATE_AUTODISCOVER_TOPICS", "--autodiscover-topics"}},
	}

	sources := []string{configFileContent, cicdConf}

	for _, g := range groups {
		for _, key := range g.keys {
			re := regexp.MustCompile(`(?is)` + regexp.QuoteMeta(key) + `\s*[:= ]\s*(\[[^\]]*\]|\{[^\}]*\}|".*?"|'.*?'|[^\s,]+)`)
			for _, src := range sources {
				if m := re.FindStringSubmatch(src); len(m) > 1 {
					val := strings.TrimSpace(m[1])
					if (strings.HasPrefix(val, `"`) && strings.HasSuffix(val, `"`)) ||
						(strings.HasPrefix(val, `'`) && strings.HasSuffix(val, `'`)) {
						val = val[1 : len(val)-1]
					}
					return true, g.name, val
				}
			}
		}
	}
	return false, "", ""
}

// detectRenovateConfigFile checks for common Renovate configuration files in the project repository
func detectRenovateConfigFile(git *gitlab.Client, project *gitlab.Project) (*gitlab.File, string) {
	// https://docs.renovatebot.com/configuration-options/
	configFiles := []string{
		"renovate.json",
		"renovate.json5",
		".github/renovate.json",
		".github/renovate.json5",
		".gitlab/renovate.json",
		".gitlab/renovate.json5",
		".renovaterc",
		".renovaterc.json",
		".renovaterc.json5",
		"config.js",
	}

	opts := gitlab.GetFileOptions{Ref: gitlab.Ptr(project.DefaultBranch)}
	for _, configFile := range configFiles {
		file, _, err := git.RepositoryFiles.GetFile(project.ID, configFile, &opts)
		if err != nil {
			continue
		}

		if file != nil {
			conf, err := b64.StdEncoding.DecodeString(file.Content)
			if err != nil {
				log.Error().Stack().Err(err).Msg("Failed decoding renovate config base64 content")
				return file, ""
			}

			if strings.HasSuffix(strings.ToLower(configFile), ".json5") {
				var js interface{}
				if err := json5.Unmarshal(conf, &js); err != nil {
					log.Debug().Stack().Err(err).Msg("Failed parsing renovate config file as JSON5")
					continue
				}

				normalized, _ := json.Marshal(js)
				conf = normalized
			}

			return file, string(conf)
		}
	}

	return nil, ""
}

func fetchCurrentSelfHostedOptions(opts EnumOptions) []string {
	if len(opts.SelfHostedOptions) > 0 {
		return opts.SelfHostedOptions
	}

	log.Debug().Msg("Fetching current self-hosted configuration from GitHub")

	client := httpclient.GetPipeleekHTTPClient("", nil, nil)
	res, err := client.Get("https://raw.githubusercontent.com/renovatebot/renovate/refs/heads/main/docs/usage/self-hosted-configuration.md")
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Failed fetching self-hosted configuration documentation")
		return []string{}
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != 200 {
		log.Fatal().Int("status", res.StatusCode).Msg("Failed fetching self-hosted configuration documentation")
		return []string{}
	}
	data, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Failed reading self-hosted configuration documentation")
		return []string{}
	}

	opts.SelfHostedOptions = extractSelfHostedOptions(data)
	return opts.SelfHostedOptions
}

func extractSelfHostedOptions(data []byte) []string {
	var re = regexp.MustCompile(`(?m)## .*`)
	matches := re.FindAllString(string(data), -1)

	var options []string
	for _, match := range matches {
		options = append(options, strings.ReplaceAll(strings.TrimSpace(match), "## ", ""))
	}

	return options
}

func isSelfHostedConfig(config string, opts EnumOptions) bool {
	selfHostedOptions := fetchCurrentSelfHostedOptions(opts)
	for _, option := range selfHostedOptions {
		// Check if the content contains any of the self-hosted options
		if format.ContainsI(config, option) {
			return true
		}
	}
	return false
}

func extendRenovateConfig(renovateConfig string, project *gitlab.Project, opts EnumOptions) string {
	return renovateutil.ExtendRenovateConfig(renovateConfig, opts.ExtendRenovateConfigService, project.WebURL)
}

func validateRenovateConfigService(serviceUrl string) error {
	client := httpclient.GetPipeleekHTTPClient("", nil, nil)

	u, err := url.Parse(serviceUrl)
	if err != nil {
		log.Error().Stack().Err(err).Msg("Failed to parse renovate config service URL")
		return err
	}
	u = u.JoinPath("health")

	resp, err := client.Get(u.String())

	if err != nil {
		log.Error().Stack().Err(err).Msg("Renovate config service healthcheck failed")
		return err
	}

	if resp.StatusCode != 200 {
		log.Error().Int("status", resp.StatusCode).Str("endpoint", u.String()).Msg("Renovate config service healthcheck failed")
		return fmt.Errorf("renovate config service healthcheck failed: %d", resp.StatusCode)
	}

	return nil
}

func dumpConfigFileContents(project *gitlab.Project, ciCdYml string, renovateConfigFile string, renovateConfigFileName string) {
	projectDir := filepath.Join("renovate-enum-out", project.PathWithNamespace)
	if err := os.MkdirAll(projectDir, 0700); err != nil {
		log.Fatal().Err(err).Str("dir", projectDir).Msg("Failed to create project directory")
	} else {
		if len(ciCdYml) > 0 {
			ciCdPath := filepath.Join(projectDir, "gitlab-ci.yml")
			if err := os.WriteFile(ciCdPath, []byte(ciCdYml), format.FileUserReadWrite); err != nil {
				log.Error().Err(err).Str("file", ciCdPath).Msg("Failed to write CI/CD YAML to disk")
			}
		}

		if len(renovateConfigFile) > 0 {
			safeFilename := renovateConfigFileName
			if safeFilename == "" {
				safeFilename = "renovate.json"
			}
			configPath := filepath.Join(projectDir, safeFilename)
			if err := os.WriteFile(configPath, []byte(renovateConfigFile), format.FileUserReadWrite); err != nil {
				log.Error().Err(err).Str("file", configPath).Msg("Failed to write Renovate config to disk")
			}
		}
	}
}

func validateOrderBy(orderBy string) {
	allowedOrderBy := map[string]struct{}{
		"id": {}, "name": {}, "path": {}, "created_at": {}, "updated_at": {}, "star_count": {}, "last_activity_at": {}, "similarity": {},
	}
	if _, ok := allowedOrderBy[orderBy]; !ok {
		log.Fatal().Str("orderBy", orderBy).Msg("Invalid value for --order-by. Allowed: id, name, path, created_at, updated_at, star_count, last_activity_at, similarity")
	}
}
