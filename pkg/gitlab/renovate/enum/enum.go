package renovate

import (
	"context"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/format"
	"github.com/CompassSecurity/pipeleek/pkg/gitlab/renovate/filter"
	"github.com/CompassSecurity/pipeleek/pkg/gitlab/util"
	"github.com/CompassSecurity/pipeleek/pkg/httpclient"
	renovateutil "github.com/CompassSecurity/pipeleek/pkg/renovate"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/wandb/parallel"
	"github.com/yosuke-furukawa/json5/encoding/json5"

	gitlab "gitlab.com/gitlab-org/api/client-go"
)

const projectProcessingConcurrency = 5

type renovateEnumStatusTracker struct {
	startedAt            atomic.Int64
	projectsDiscovered   atomic.Int64
	projectsProcessed    atomic.Int64
	renovateConfigsFound atomic.Int64
}

var statusTracker renovateEnumStatusTracker

func StatusHook() *zerolog.Event {
	projectsDiscovered := statusTracker.projectsDiscovered.Load()
	projectsProcessed := statusTracker.projectsProcessed.Load()
	projectsOutstanding := projectsDiscovered - projectsProcessed
	if projectsOutstanding < 0 {
		projectsOutstanding = 0
	}

	event := log.Info().
		Int64("projectsDiscovered", projectsDiscovered).
		Int64("projectsProcessed", projectsProcessed).
		Int64("projectsOutstanding", projectsOutstanding).
		Int64("renovateConfigsFound", statusTracker.renovateConfigsFound.Load())
	if startedAt := statusTracker.startedAt.Load(); startedAt != 0 {
		event = event.Dur("elapsed", time.Since(time.Unix(0, startedAt)))
	}
	return event
}

func resetStatus() {
	statusTracker.startedAt.Store(time.Now().UnixNano())
	statusTracker.projectsDiscovered.Store(0)
	statusTracker.projectsProcessed.Store(0)
	statusTracker.renovateConfigsFound.Store(0)
}

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
	resetStatus()
	if len(opts.SelfHostedOptions) == 0 {
		opts.SelfHostedOptions = fetchCurrentSelfHostedOptions(opts)
	}
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

	if err := validateOrderBy(opts.OrderBy); err != nil {
		log.Fatal().Stack().Err(err).Msg("Invalid order-by value")
	}

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
	log.Info().Str("project", projectName).Msg("Scanning specific project for Renovate configuration")
	project, resp, err := git.Projects.GetProject(projectName, &gitlab.GetProjectOptions{})
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Failed fetching project by repository name")
	}
	if resp.StatusCode == 404 {
		log.Fatal().Msg("Project not found")
	}
	statusTracker.projectsDiscovered.Add(1)
	identifyRenovateBotJob(git, project, opts)
	statusTracker.projectsProcessed.Add(1)
}

func scanNamespace(git *gitlab.Client, namespace string, opts EnumOptions) {
	log.Info().Str("group", namespace).Msg("Scanning specific group for Renovate configuration")
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

	err = processProjectsConcurrently(func(callback util.ProjectIteratorFunc) error {
		return util.IterateGroupProjects(git, group.ID, projectOpts, callback)
	}, func(project *gitlab.Project) {
		log.Debug().Str("url", project.WebURL).Msg("Check project")
		identifyRenovateBotJob(git, project, opts)
	})
	if err != nil {
		log.Error().Stack().Err(err).Msg("Failed iterating group projects")
		return
	}

	log.Info().Msg("Fetched all group projects")
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

	err := processProjectsConcurrently(func(callback util.ProjectIteratorFunc) error {
		return util.IterateProjects(git, projectOpts, callback)
	}, func(project *gitlab.Project) {
		log.Debug().Str("url", project.WebURL).Msg("Check project")
		identifyRenovateBotJob(git, project, opts)
	})
	if err != nil {
		log.Error().Stack().Err(err).Msg("Failed iterating projects")
		return
	}

	log.Info().Msg("Fetched all projects")
}

func processProjectsConcurrently(iterate func(util.ProjectIteratorFunc) error, process func(*gitlab.Project)) error {
	workers := parallel.Limited(context.Background(), projectProcessingConcurrency)
	err := iterate(func(project *gitlab.Project) error {
		statusTracker.projectsDiscovered.Add(1)
		workers.Go(func(context.Context) {
			process(project)
			statusTracker.projectsProcessed.Add(1)
		})
		return nil
	})
	workers.Wait()
	return err
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
	var configFilePath string
	var configFiles []renovateConfigFile
	if !opts.Fast {
		configFiles = detectRenovateConfigFiles(git, project)
		if len(configFiles) > 0 {
			configFile = configFiles[0].file
			configFileContent = configFiles[0].content
			configFilePath = configFiles[0].path
		}

		if opts.ExtendRenovateConfigService != "" {
			// Replace any occurrence of "local>" with "gitlab>" this best effort
			configFileContent = strings.ReplaceAll(configFileContent, "local>", "gitlab>")
			configFileContent = extendRenovateConfig(configFileContent, project, opts)
		}
	}

	if hasCiCdRenovateConfig || configFile != nil {
		statusTracker.renovateConfigsFound.Add(1)
		if opts.Dump {
			filename := ""
			if configFile != nil {
				filename = configFile.FileName
			}
			dumpConfigFileContents(project, ciCdYml, configFileContent, filename, "renovate-enum-out")
		}

		autodiscoveryConfigContent := combineAutodiscoveryConfigFiles(configFiles, configFilePath, configFileContent)
		isSelfHostedConfigContent := strings.Join([]string{ciCdYml, autodiscoveryConfigContent}, "\n")

		autodiscovery := detectAutodiscovery(ciCdYml, autodiscoveryConfigContent)
		filterType := ""
		filterValue := ""
		filterUsesCommaDelimiter := false
		hasAutodiscoveryFilters := false
		if autodiscovery {
			hasAutodiscoveryFilters, filterType, filterValue, filterUsesCommaDelimiter = renovateutil.DetectAutodiscoveryFiltersWithSource(ciCdYml, autodiscoveryConfigContent)
		}
		analysisFilterValue := filterValue
		if filterType == "autodiscoverFilter" && filterUsesCommaDelimiter {
			analysisFilterValue = commaDelimitedFilterPatterns(filterValue)
		}

		var filterFindings []filter.Finding
		if autodiscovery && !hasEffectiveAutodiscoveryScope(filterType, analysisFilterValue) {
			filterFindings = filter.AnalyzeUnfilteredAutodiscovery()
		} else if hasAutodiscoveryFilters && filterType == "autodiscoverFilter" {
			filterFindings = filter.AnalyzeWithGitLabProjectPaths(analysisFilterValue, gitLabProjectPathValues(project))
		}

		event := log.Info().
			Bool("hasAutodiscovery", autodiscovery).
			Str("pipelines", string(project.BuildsAccessLevel)).
			Str("url", project.WebURL)
		if len(opts.SelfHostedOptions) > 0 {
			event = event.Bool("isSelfHosted", isSelfHostedConfig(isSelfHostedConfigContent, opts))
		}
		if hasAutodiscoveryFilters {
			event = event.Str("autodiscoveryFilterType", filterType).Str("autodiscoveryFilterValue", filterValue)
			if ruleID, ok := vulnerableFindingRuleID(filterFindings); ok {
				event = event.Str("autodiscoveryFilterBypass", ruleID)
			}
			if ruleID, ok := reviewFindingRuleID(filterFindings); ok {
				event = event.Str("autodiscoveryFilterReview", ruleID)
			}
		} else if ruleID, ok := vulnerableFindingRuleID(filterFindings); ok {
			event = event.Str("autodiscoveryFilterBypass", ruleID)
		} else if ruleID, ok := reviewFindingRuleID(filterFindings); ok {
			event = event.Str("autodiscoveryScopeReview", ruleID)
		}
		event.Msg("Renovate configuration")

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

func gitLabProjectPathValues(project *gitlab.Project) filter.GitLabProjectPathValues {
	projectPath := project.PathWithNamespace
	namespacePath := ""
	if project.Namespace != nil {
		namespacePath = project.Namespace.FullPath
	}
	if namespacePath == "" {
		namespacePath = projectPath
		if slash := strings.LastIndexByte(namespacePath, '/'); slash >= 0 {
			namespacePath = namespacePath[:slash]
		} else {
			namespacePath = ""
		}
	}
	rootNamespace, _, _ := strings.Cut(namespacePath, "/")

	return filter.GitLabProjectPathValues{
		ProjectPath:      projectPath,
		ProjectNamespace: namespacePath,
		RootNamespace:    rootNamespace,
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
	return renovateutil.DetectAutodiscovery(cicdConf, configFileContent)
}

func detectAutodiscoveryFilters(cicdConf, configFileContent string) (bool, string, string) {
	return renovateutil.DetectAutodiscoveryFilters(cicdConf, configFileContent)
}

type renovateConfigFile struct {
	path    string
	file    *gitlab.File
	content string
}

var renovateConfigPaths = []string{
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

// detectRenovateConfigFiles returns all supported Renovate config files; the first remains the primary config.
func detectRenovateConfigFiles(git *gitlab.Client, project *gitlab.Project) []renovateConfigFile {
	// https://docs.renovatebot.com/configuration-options/
	opts := gitlab.GetFileOptions{Ref: gitlab.Ptr(project.DefaultBranch)}
	var configs []renovateConfigFile
	for _, path := range renovateConfigPaths {
		file, _, err := git.RepositoryFiles.GetFile(project.ID, path, &opts)
		if err != nil {
			continue
		}

		if file != nil {
			conf, err := b64.StdEncoding.DecodeString(file.Content)
			if err != nil {
				log.Debug().Err(err).Str("file", path).Msg("Failed decoding Renovate config file")
				continue
			}

			if strings.HasSuffix(strings.ToLower(path), ".json5") {
				var js interface{}
				if err := json5.Unmarshal(conf, &js); err != nil {
					log.Debug().Err(err).Str("file", path).Msg("Failed parsing Renovate config file as JSON5")
					continue
				}

				normalized, _ := json.Marshal(js)
				conf = normalized
			}

			configs = append(configs, renovateConfigFile{path: path, file: file, content: string(conf)})
		}
	}

	return configs
}

func combineAutodiscoveryConfigFiles(configs []renovateConfigFile, primaryPath, primaryContent string) string {
	var contents []string
	if primaryPath == "config.js" {
		if primaryContent != "" {
			contents = append(contents, primaryContent)
		}
	} else {
		for _, config := range configs {
			if config.path == "config.js" && config.content != "" {
				contents = append(contents, config.content)
				break
			}
		}
	}

	for _, config := range configs {
		if config.path == "config.js" || config.path == primaryPath {
			continue
		}
		if config.content != "" {
			contents = append(contents, config.content)
		}
	}
	if primaryPath != "config.js" && primaryContent != "" {
		contents = append(contents, primaryContent)
	}
	return strings.Join(contents, "\n")
}

func fetchCurrentSelfHostedOptions(opts EnumOptions) []string {
	return renovateutil.FetchCurrentSelfHostedOptions(opts.SelfHostedOptions, httpclient.GetPipeleekHTTPClient("", nil, nil))
}

func extractSelfHostedOptions(data []byte) []string {
	return renovateutil.ExtractSelfHostedOptions(data)
}

func isSelfHostedConfig(config string, opts EnumOptions) bool {
	return renovateutil.IsSelfHostedConfig(config, opts.SelfHostedOptions)
}

func extendRenovateConfig(renovateConfig string, project *gitlab.Project, opts EnumOptions) string {
	return renovateutil.ExtendRenovateConfig(renovateConfig, opts.ExtendRenovateConfigService, project.WebURL, httpclient.GetPipeleekHTTPClient("", nil, nil))
}

func validateRenovateConfigService(serviceUrl string) error {
	return renovateutil.ValidateRenovateConfigService(serviceUrl, httpclient.GetPipeleekHTTPClient("", nil, nil))
}

func dumpConfigFileContents(project *gitlab.Project, ciCdYml string, renovateConfigFile string, renovateConfigFileName string, outDir string) {
	projectDir := filepath.Join(outDir, project.PathWithNamespace)
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

func validateOrderBy(orderBy string) error {
	allowedOrderBy := map[string]struct{}{
		"id": {}, "name": {}, "path": {}, "created_at": {}, "updated_at": {}, "star_count": {}, "last_activity_at": {}, "similarity": {},
	}
	if _, ok := allowedOrderBy[orderBy]; !ok {
		return fmt.Errorf("invalid value for --order-by: %q. Allowed: id, name, path, created_at, updated_at, star_count, last_activity_at, similarity", orderBy)
	}
	return nil
}

func hasEffectiveAutodiscoveryScope(filterType, filterValue string) bool {
	value := strings.TrimSpace(filterValue)
	if value == "" || value == "<nil>" || strings.EqualFold(value, "null") {
		return false
	}
	if strings.HasPrefix(value, "[") {
		var patterns []string
		if err := json5.Unmarshal([]byte(value), &patterns); err == nil {
			for _, pattern := range patterns {
				if strings.TrimSpace(pattern) != "" {
					return filterType != "autodiscoverProjects"
				}
			}
			return false
		}
	}

	switch filterType {
	case "autodiscoverFilter":
		return true
	case "autodiscoverNamespaces", "autodiscoverTopics":
		return true
	default:
		return false
	}
}

func commaDelimitedFilterPatterns(filterValue string) string {
	patterns := strings.Split(filterValue, ",")
	for i := range patterns {
		patterns[i] = strings.TrimSpace(patterns[i])
	}
	serialized, err := json.Marshal(patterns)
	if err != nil {
		return filterValue
	}
	return string(serialized)
}

// vulnerableFindingRuleID returns the first vulnerable rule ID from findings.
func vulnerableFindingRuleID(findings []filter.Finding) (string, bool) {
	for _, f := range findings {
		if f.Verdict == filter.Vulnerable {
			return f.RuleID, true
		}
	}
	return "", false
}

func reviewFindingRuleID(findings []filter.Finding) (string, bool) {
	for _, f := range findings {
		if f.Verdict == filter.NeedsReview {
			return f.RuleID, true
		}
	}
	return "", false
}
