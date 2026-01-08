package renovate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
	} else if opts.SearchQuery != "" {
		searchRepositories(ctx, client, opts.SearchQuery, opts)
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
	if opts.Owned {
		// Scan owned repositories only
		log.Info().Msg("Fetching owned repositories")
		fetchOwnedRepositories(ctx, client, opts)
	} else if opts.Member {
		// Scan repositories where user is a member or collaborator
		log.Info().Msg("Fetching member repositories")
		fetchMemberRepositories(ctx, client, opts)
	} else {
		// Default: scan all public GitHub repos
		log.Info().Msg("Fetching all public repositories")
		fetchAllPublicRepositories(ctx, client, opts)
	}
}

func fetchOwnedRepositories(ctx context.Context, client *github.Client, opts EnumOptions) {
	listOpts := &github.RepositoryListByAuthenticatedUserOptions{
		ListOptions: github.ListOptions{
			PerPage: 100,
			Page:    opts.Page,
		},
		Sort:        opts.OrderBy,
		Affiliation: "owner",
	}

	for {
		repos, resp, err := client.Repositories.ListByAuthenticatedUser(ctx, listOpts)
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

	log.Info().Msg("Fetched all owned repositories")
}

func fetchMemberRepositories(ctx context.Context, client *github.Client, opts EnumOptions) {
	listOpts := &github.RepositoryListByAuthenticatedUserOptions{
		ListOptions: github.ListOptions{
			PerPage: 100,
			Page:    opts.Page,
		},
		Sort:        opts.OrderBy,
		Visibility:  "all",
		Affiliation: "organization_member,collaborator",
	}

	for {
		repos, resp, err := client.Repositories.ListByAuthenticatedUser(ctx, listOpts)
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

	log.Info().Msg("Fetched all member repositories")
}

func fetchAllPublicRepositories(ctx context.Context, client *github.Client, opts EnumOptions) {
	// Identify the latest public repository ID
	latestProjectID := identifyNewestPublicProjectID(ctx, client)
	if latestProjectID == 0 {
		log.Warn().Msg("Could not identify latest public repository ID, starting from current ID")
		latestProjectID = 1
	}

	listAllOpts := &github.RepositoryListAllOptions{
		Since: latestProjectID,
	}

	// Keep a cache of scanned IDs to avoid duplicates due to missing IDs
	scannedIDs := make(map[int64]struct{})

	for listAllOpts.Since >= 0 {
		repos, _, err := client.Repositories.ListAll(ctx, listAllOpts)
		if err != nil {
			log.Error().Stack().Err(err).Msg("Failed iterating public repositories")
			return
		}

		if len(repos) == 0 {
			break
		}

		// Sort in descending order to process newest first
		sort.SliceStable(repos, func(i, j int) bool {
			return *repos[i].ID > *repos[j].ID
		})

		for _, repo := range repos {
			// Skip if we've already scanned this repo
			if _, exists := scannedIDs[*repo.ID]; exists {
				continue
			}
			scannedIDs[*repo.ID] = struct{}{}

			log.Debug().Str("url", repo.GetHTMLURL()).Msg("Check repository")
			identifyRenovateBotWorkflow(ctx, client, repo, opts)
			listAllOpts.Since = *repo.ID
		}

		// Move to the next batch (decrement since by page size)
		listAllOpts.Since = listAllOpts.Since - 100
		if listAllOpts.Since < 0 {
			break
		}
	}

	log.Info().Msg("Fetched all public repositories")
}

func identifyNewestPublicProjectID(ctx context.Context, client *github.Client) int64 {
	// Get the latest event from GitHub activity to find the newest repo
	listOpts := &github.ListOptions{PerPage: 100}
	events, _, err := client.Activity.ListEvents(ctx, listOpts)
	if err != nil {
		log.Error().Stack().Err(err).Msg("Failed to identify newest public repository")
		return 0
	}

	for _, event := range events {
		if event.Type != nil && *event.Type == "CreateEvent" && event.Repo != nil && event.Repo.ID != nil {
			// Found a create event, get the repository to confirm it exists
			repo, _, err := client.Repositories.GetByID(ctx, *event.Repo.ID)
			if err != nil {
				log.Debug().Err(err).Msg("Failed to fetch repository details")
				continue
			}
			log.Info().Int64("id", *repo.ID).Str("url", repo.GetHTMLURL()).Msg("Identified latest public repository")
			return *repo.ID
		}
	}

	return 0
}

func searchRepositories(ctx context.Context, client *github.Client, query string, opts EnumOptions) {
	log.Info().Str("query", query).Msg("Searching repositories")

	searchOpts := &github.SearchOptions{
		ListOptions: github.ListOptions{
			PerPage: 100,
			Page:    opts.Page,
		},
	}

	firstPage := true
	for {
		searchResults, resp, err := client.Search.Repositories(ctx, query, searchOpts)
		if err != nil {
			log.Error().Stack().Err(err).Msg("Failed searching repositories")
			return
		}

		if firstPage {
			log.Info().Int("total_matching_repos", searchResults.GetTotal()).Msg("Found matching repositories to scan")
			firstPage = false
		}

		for _, repo := range searchResults.Repositories {
			log.Debug().Str("url", repo.GetHTMLURL()).Msg("Check repository")
			identifyRenovateBotWorkflow(ctx, client, repo, opts)
		}

		if resp.NextPage == 0 {
			break
		}
		searchOpts.Page = resp.NextPage
	}

	log.Info().Msg("Fetched all search results")
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

			if fileContent != nil {
				contentStr, err := fileContent.GetContent()
				if err != nil {
					log.Debug().Err(err).Str("file", content.GetPath()).Msg("Failed to get workflow file content")
					continue
				}
				if contentStr != "" {
					allWorkflows.WriteString(contentStr)
					allWorkflows.WriteString("\n")
				}
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

		if fileContent != nil {
			contentStr, err := fileContent.GetContent()
			if err != nil {
				log.Debug().Err(err).Str("file", configFile).Msg("Failed to get config file content")
				continue
			}
			if contentStr != "" {
				conf := []byte(contentStr)

				if strings.HasSuffix(strings.ToLower(configFile), ".json5") {
					var js interface{}
					if err := json5.Unmarshal(conf, &js); err != nil {
						log.Debug().Stack().Err(err).Str("file", configFile).Msg("Failed parsing renovate config file as JSON5, using raw content")
						// Fallback to raw content if JSON5 parsing fails
						return fileContent, string(conf)
					}

					normalized, _ := json.Marshal(js)
					conf = normalized
				}

				return fileContent, string(conf)
			}
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

// ParseWorkflowYAML attempts to parse a workflow YAML string and return structured data.
func ParseWorkflowYAML(yamlContent string) (map[string]interface{}, error) {
	var result map[string]interface{}
	err := yaml.Unmarshal([]byte(yamlContent), &result)
	if err != nil {
		return nil, fmt.Errorf("failed to parse workflow YAML: %w", err)
	}
	return result, nil
}
