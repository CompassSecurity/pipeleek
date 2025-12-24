package renovate

import (
	"context"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CompassSecurity/pipeleek/pkg/format"
	pkgrenovate "github.com/CompassSecurity/pipeleek/pkg/renovate"
	"github.com/google/go-github/v69/github"
	"github.com/rs/zerolog/log"
	"github.com/yosuke-furukawa/json5/encoding/json5"
	"gopkg.in/yaml.v3"
)

// EnumOptions contains all options for the renovate enum command.
type EnumOptions struct {
	GitHubURL                   string
	GitHubToken                 string
	Owned                       bool
	Member                      bool
	SearchQuery                 string
	Fast                        bool
	Dump                        bool
	SelfHostedOptions           []string
	Page                        int
	Repository                  string
	Organization                string
	OrderBy                     string
	ExtendRenovateConfigService string
}

// RunEnumerate performs the renovate enumeration with the given options.
func RunEnumerate(client *github.Client, opts EnumOptions) {
	ctx := context.Background()

	if opts.ExtendRenovateConfigService != "" {
		err := pkgrenovate.ValidateRenovateConfigService(opts.ExtendRenovateConfigService)
		if err != nil {
			log.Fatal().Stack().Err(err).Msg("Invalid extendRenovateConfigService URL")
		}
		log.Info().Str("service", opts.ExtendRenovateConfigService).Msg("Using renovate config extension service")
	}

	if opts.Repository != "" {
		scanSingleRepository(ctx, client, opts.Repository, opts)
	} else if opts.Organization != "" {
		scanOrganization(ctx, client, opts.Organization, opts)
	} else {
		fetchRepositories(ctx, client, opts)
	}

	log.Info().Msg("Done, Bye Bye 🏳️‍🌈🔥")
}

func scanSingleRepository(ctx context.Context, client *github.Client, repoName string, opts EnumOptions) {
	log.Info().Str("repository", repoName).Msg("Scanning specific repository for Renovate configuration")

	parts := strings.Split(repoName, "/")
	if len(parts) != 2 {
		log.Fatal().Str("repository", repoName).Msg("Repository must be in format owner/repo")
	}
	owner, repo := parts[0], parts[1]

	repository, _, err := client.Repositories.Get(ctx, owner, repo)
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Failed fetching repository")
	}

	identifyRenovateBotWorkflow(ctx, client, repository, opts)
}

func scanOrganization(ctx context.Context, client *github.Client, org string, opts EnumOptions) {
	log.Info().Str("organization", org).Msg("Scanning organization repositories for Renovate configuration")

	listOpts := &github.RepositoryListByOrgOptions{
		ListOptions: github.ListOptions{
			PerPage: 100,
			Page:    opts.Page,
		},
		Sort: opts.OrderBy,
	}

	for {
		repos, resp, err := client.Repositories.ListByOrg(ctx, org, listOpts)
		if err != nil {
			log.Error().Stack().Err(err).Msg("Failed iterating organization repositories")
			return
		}

		for _, repo := range repos {
			log.Debug().Str("url", repo.GetHTMLURL()).Msg("Check repository")
			identifyRenovateBotWorkflow(ctx, client, repo, opts)
		}

		if resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}

	log.Info().Msg("Fetched all organization repositories")
}

func fetchRepositories(ctx context.Context, client *github.Client, opts EnumOptions) {
	log.Info().Msg("Fetching repositories")

	listOpts := &github.RepositoryListOptions{
		ListOptions: github.ListOptions{
			PerPage: 100,
			Page:    opts.Page,
		},
		Sort: opts.OrderBy,
	}

	// Set visibility based on member flag
	if opts.Member {
		listOpts.Visibility = "all"
		listOpts.Affiliation = "organization_member,collaborator"
	}

	for {
		repos, resp, err := client.Repositories.List(ctx, "", listOpts)
		if err != nil {
			log.Error().Stack().Err(err).Msg("Failed iterating repositories")
			return
		}

		for _, repo := range repos {
			log.Debug().Str("url", repo.GetHTMLURL()).Msg("Check repository")
			identifyRenovateBotWorkflow(ctx, client, repo, opts)
		}

		if resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}

	log.Info().Msg("Fetched all repositories")
}

func identifyRenovateBotWorkflow(ctx context.Context, client *github.Client, repo *github.Repository, opts EnumOptions) {
	// Fetch workflow files
	workflowYml := fetchWorkflowFiles(ctx, client, repo)

	hasCiCdRenovateConfig := pkgrenovate.DetectCiCdConfig(workflowYml)
	var configFile *github.RepositoryContent = nil
	var configFileContent string
	if !opts.Fast {
		configFile, configFileContent = detectRenovateConfigFile(ctx, client, repo)

		if opts.ExtendRenovateConfigService != "" {
			// Replace any occurrence of "local>" with "github>" this is best effort
			configFileContent = strings.ReplaceAll(configFileContent, "local>", "github>")
			configFileContent = pkgrenovate.ExtendRenovateConfig(configFileContent, opts.ExtendRenovateConfigService, repo.GetHTMLURL())
		}
	}

	if hasCiCdRenovateConfig || configFile != nil {
		if opts.Dump {
			filename := ""
			if configFile != nil {
				filename = configFile.GetName()
			}
			dumpConfigFileContents(repo, workflowYml, configFileContent, filename)
		}

		selfHostedConfigFile := false
		if configFile != nil {
			opts.SelfHostedOptions = pkgrenovate.FetchCurrentSelfHostedOptions(opts.SelfHostedOptions)
			selfHostedConfigFile = pkgrenovate.IsSelfHostedConfig(configFileContent, opts.SelfHostedOptions)
		}

		autodiscovery := pkgrenovate.DetectAutodiscovery(workflowYml, configFileContent)
		filterType := ""
		filterValue := ""
		hasAutodiscoveryFilters := false
		if autodiscovery {
			hasAutodiscoveryFilters, filterType, filterValue = pkgrenovate.DetectAutodiscoveryFilters(workflowYml, configFileContent)
		}

		actionsEnabled := !repo.GetDisabled() && !repo.GetArchived()

		log.Warn().
			Bool("actionsEnabled", actionsEnabled).
			Bool("hasAutodiscovery", autodiscovery).
			Bool("hasAutodiscoveryFilters", hasAutodiscoveryFilters).
			Str("autodiscoveryFilterType", filterType).
			Str("autodiscoveryFilterValue", filterValue).
			Bool("hasConfigFile", configFile != nil).
			Bool("selfHostedConfigFile", selfHostedConfigFile).
			Str("url", repo.GetHTMLURL()).
			Msg("Identified Renovate (bot) configuration")

		if hasCiCdRenovateConfig {
			yml, err := format.PrettyPrintYAML(workflowYml)
			if err != nil {
				log.Error().Stack().Err(err).Msg("Failed pretty printing workflow YAML")
				return
			}
			log.Debug().Msg(format.GetPlatformAgnosticNewline() + yml)
		}
	}
}

func fetchWorkflowFiles(ctx context.Context, client *github.Client, repo *github.Repository) string {
	owner := repo.GetOwner().GetLogin()
	repoName := repo.GetName()

	// Get workflow files from .github/workflows directory
	_, dirContents, _, err := client.Repositories.GetContents(ctx, owner, repoName, ".github/workflows", nil)
	if err != nil {
		// No workflows directory
		return ""
	}

	var allWorkflows strings.Builder
	for _, content := range dirContents {
		if content.GetType() == "file" && (strings.HasSuffix(content.GetName(), ".yml") || strings.HasSuffix(content.GetName(), ".yaml")) {
			fileContent, _, _, err := client.Repositories.GetContents(ctx, owner, repoName, content.GetPath(), nil)
			if err != nil {
				log.Debug().Err(err).Str("file", content.GetPath()).Msg("Failed to fetch workflow file")
				continue
			}

			if fileContent != nil && fileContent.GetContent() != "" {
				decoded, err := b64.StdEncoding.DecodeString(fileContent.GetContent())
				if err != nil {
					log.Debug().Err(err).Str("file", content.GetPath()).Msg("Failed to decode workflow file")
					continue
				}
				allWorkflows.WriteString(string(decoded))
				allWorkflows.WriteString("\n")
			}
		}
	}

	return allWorkflows.String()
}

func detectRenovateConfigFile(ctx context.Context, client *github.Client, repo *github.Repository) (*github.RepositoryContent, string) {
	owner := repo.GetOwner().GetLogin()
	repoName := repo.GetName()

	for _, configFile := range pkgrenovate.RenovateConfigFiles() {
		fileContent, _, _, err := client.Repositories.GetContents(ctx, owner, repoName, configFile, nil)
		if err != nil {
			continue
		}

		if fileContent != nil && fileContent.GetContent() != "" {
			conf, err := b64.StdEncoding.DecodeString(fileContent.GetContent())
			if err != nil {
				log.Error().Stack().Err(err).Msg("Failed decoding renovate config base64 content")
				return fileContent, ""
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

			return fileContent, string(conf)
		}
	}

	return nil, ""
}

func dumpConfigFileContents(repo *github.Repository, workflowYml string, renovateConfigFile string, renovateConfigFileName string) {
	repoFullName := repo.GetFullName()
	projectDir := filepath.Join("renovate-enum-out", repoFullName)
	if err := os.MkdirAll(projectDir, 0700); err != nil {
		log.Fatal().Err(err).Str("dir", projectDir).Msg("Failed to create project directory")
	} else {
		if len(workflowYml) > 0 {
			workflowPath := filepath.Join(projectDir, "workflows.yml")
			if err := os.WriteFile(workflowPath, []byte(workflowYml), format.FileUserReadWrite); err != nil {
				log.Error().Err(err).Str("file", workflowPath).Msg("Failed to write workflow YAML to disk")
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
		"created": {}, "updated": {}, "pushed": {}, "full_name": {},
	}
	if orderBy != "" {
		if _, ok := allowedOrderBy[orderBy]; !ok {
			log.Fatal().Str("orderBy", orderBy).Msg("Invalid value for --order-by. Allowed: created, updated, pushed, full_name")
		}
	}
}

// ParseWorkflowYAML attempts to parse a workflow YAML string and return structured data.
func ParseWorkflowYAML(yamlContent string) (map[string]interface{}, error) {
	var result map[string]interface{}
	err := yaml.Unmarshal([]byte(yamlContent), &result)
	if err != nil {
		return nil, fmt.Errorf("failed to parse workflow YAML: %w", err)
	}
	return result, nil
}
