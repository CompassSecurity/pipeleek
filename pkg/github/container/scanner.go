package container

import (
	"context"
	"regexp"
	"strings"

	"github.com/google/go-github/v69/github"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// RunScan performs the container scan with the given options
func RunScan(opts ScanOptions, client *github.Client) {
	ctx := context.Background()

	patterns := DefaultPatterns()
	log.Info().Int("pattern_count", len(patterns)).Msg("Loaded container scan patterns")

	if opts.Repository != "" {
		scanSingleRepo(ctx, client, opts.Repository, patterns)
	} else if opts.Organization != "" {
		scanOrganization(ctx, client, opts.Organization, patterns, opts)
	} else {
		fetchRepositories(ctx, client, patterns, opts)
	}

	log.Info().Msg("Container scan complete")
}

func scanSingleRepo(ctx context.Context, client *github.Client, repoName string, patterns []Pattern) {
	log.Info().Str("repository", repoName).Msg("Scanning specific repository for dangerous container patterns")
	
	parts := strings.Split(repoName, "/")
	if len(parts) != 2 {
		log.Fatal().Str("repository", repoName).Msg("Invalid repository format, expected owner/repo")
	}
	owner, repo := parts[0], parts[1]

	repository, _, err := client.Repositories.Get(ctx, owner, repo)
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Failed fetching repository")
	}
	
	scanRepository(ctx, client, repository, patterns)
}

func scanOrganization(ctx context.Context, client *github.Client, orgName string, patterns []Pattern, opts ScanOptions) {
	log.Info().Str("organization", orgName).Msg("Scanning organization for dangerous container patterns")
	
	listOpts := &github.RepositoryListByOrgOptions{
		ListOptions: github.ListOptions{
			PerPage: 100,
			Page:    opts.Page,
		},
	}

	repos, _, err := client.Repositories.ListByOrg(ctx, orgName, listOpts)
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Failed fetching organization repositories")
	}

	for _, repo := range repos {
		log.Debug().Str("url", repo.GetHTMLURL()).Msg("Check repository")
		scanRepository(ctx, client, repo, patterns)
	}
}

func fetchRepositories(ctx context.Context, client *github.Client, patterns []Pattern, opts ScanOptions) {
	log.Info().Msg("Fetching repositories")
	
	searchOpts := &github.SearchOptions{
		ListOptions: github.ListOptions{
			PerPage: 100,
			Page:    opts.Page,
		},
	}

	var query string
	if opts.ProjectSearchQuery != "" {
		query = opts.ProjectSearchQuery
	} else {
		// Default query based on options
		if opts.Owned {
			query = "user:@me"
		} else if opts.Member {
			query = "user:@me"
		}
	}

	if query == "" {
		log.Fatal().Msg("No search criteria specified. Use --owned, --member, --org, --repo, or --search")
	}

	result, _, err := client.Search.Repositories(ctx, query, searchOpts)
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Failed searching repositories")
	}

	for _, repo := range result.Repositories {
		log.Debug().Str("url", repo.GetHTMLURL()).Msg("Check repository")
		scanRepository(ctx, client, repo, patterns)
	}
}

func scanRepository(ctx context.Context, client *github.Client, repo *github.Repository, patterns []Pattern) {
	owner := repo.GetOwner().GetLogin()
	repoName := repo.GetName()
	
	log.Debug().Str("repository", repo.GetFullName()).Msg("Scanning repository for Dockerfiles")
	
	// Try to fetch common Dockerfile/Containerfile names
	dockerfileNames := []string{"Dockerfile", "Containerfile", "dockerfile", "containerfile"}

	for _, fileName := range dockerfileNames {
		fileContent, _, _, err := client.Repositories.GetContents(ctx, owner, repoName, fileName, nil)
		if err != nil {
			log.Trace().Str("repository", repo.GetFullName()).Str("file", fileName).Err(err).Msg("Error fetching file")
			continue
		}
		if fileContent == nil {
			log.Trace().Str("repository", repo.GetFullName()).Str("file", fileName).Msg("File not found")
			continue
		}

		// Found a Dockerfile/Containerfile, check for .dockerignore and multistage
		hasDockerignore := checkDockerignoreExists(ctx, client, owner, repoName)
		isMultistage := checkIsMultistage(fileContent)
		
		scanDockerfile(ctx, client, repo, fileContent, fileName, patterns, hasDockerignore, isMultistage)
		return // Found one, don't need to check others
	}

	log.Trace().Str("repository", repo.GetFullName()).Msg("No Dockerfile or Containerfile found")
}

// checkDockerignoreExists checks if a .dockerignore file exists in the repository
func checkDockerignoreExists(ctx context.Context, client *github.Client, owner, repo string) bool {
	_, _, _, err := client.Repositories.GetContents(ctx, owner, repo, ".dockerignore", nil)
	return err == nil
}

// checkIsMultistage checks if the Dockerfile uses multistage builds by counting FROM statements
func checkIsMultistage(fileContent *github.RepositoryContent) bool {
	content, err := fileContent.GetContent()
	if err != nil {
		return false
	}
	
	lines := strings.Split(content, "\n")
	
	fromCount := 0
	fromPattern := regexp.MustCompile(`(?i)^\s*FROM\s+`)
	
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		// Skip empty lines and comments
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") {
			continue
		}
		
		if fromPattern.MatchString(line) {
			fromCount++
			if fromCount > 1 {
				return true
			}
		}
	}
	
	return false
}

func scanDockerfile(ctx context.Context, client *github.Client, repo *github.Repository, fileContent *github.RepositoryContent, fileName string, patterns []Pattern, hasDockerignore bool, isMultistage bool) {
	log.Debug().Str("repository", repo.GetFullName()).Str("file", fileName).Msg("Scanning Dockerfile")
	
	content, err := fileContent.GetContent()
	if err != nil {
		log.Error().Str("repository", repo.GetFullName()).Str("file", fileName).Err(err).Msg("Failed to get file content")
		return
	}
	
	lines := strings.Split(content, "\n")

	// Check against all patterns
	for _, pattern := range patterns {
		found := false
		var matchedLine string
		
		// Search through lines to find a match
		for _, line := range lines {
			trimmedLine := strings.TrimSpace(line)
			// Skip empty lines and comments
			if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") {
				continue
			}
			
			if pattern.Pattern.MatchString(line) {
				found = true
				matchedLine = strings.TrimSpace(line)
				break
			}
		}
		
		if found {
			finding := Finding{
				ProjectPath:     repo.GetFullName(),
				ProjectURL:      repo.GetHTMLURL(),
				FilePath:        fileName,
				FileName:        fileName,
				MatchedPattern:  pattern.Name,
				LineContent:     matchedLine,
				PatternSeverity: pattern.Severity,
				HasDockerignore: hasDockerignore,
				IsMultistage:    isMultistage,
			}

			// Fetch registry metadata for the most recent container
			finding.RegistryMetadata = fetchRegistryMetadata(ctx, client, repo)

			logFinding(finding)
		}
	}
}

func logFinding(finding Finding) {
	logEvent := log.WithLevel(zerolog.InfoLevel).
		Str("url", finding.ProjectURL).
		Str("file", finding.FilePath).
		Str("content", finding.LineContent).
		Bool("has_dockerignore", finding.HasDockerignore).
		Bool("is_multistage", finding.IsMultistage)

	// Add registry metadata if available
	if finding.RegistryMetadata != nil {
		logEvent = logEvent.
			Str("registry_tag", finding.RegistryMetadata.TagName).
			Str("registry_last_update", finding.RegistryMetadata.LastUpdate)
	}

	logEvent.Msg("Identified")
}

// fetchRegistryMetadata retrieves metadata about the most recent container image in the repository's registry
func fetchRegistryMetadata(ctx context.Context, client *github.Client, repo *github.Repository) *RegistryMetadata {
	owner := repo.GetOwner().GetLogin()
	repoName := repo.GetName()

	// List container packages for the repository
	packages, _, err := client.Organizations.ListPackages(ctx, owner, &github.PackageListOptions{
		PackageType: github.String("container"),
	})
	if err != nil {
		log.Trace().Str("repository", repo.GetFullName()).Err(err).Msg("Error accessing container registry")
		return nil
	}

	if len(packages) == 0 {
		log.Trace().Str("repository", repo.GetFullName()).Msg("No container packages found in registry")
		return nil
	}

	// Find package matching the repository name
	var targetPackage *github.Package
	for _, pkg := range packages {
		if strings.Contains(strings.ToLower(pkg.GetName()), strings.ToLower(repoName)) {
			targetPackage = pkg
			break
		}
	}

	if targetPackage == nil {
		// If no exact match, use the first package
		targetPackage = packages[0]
	}

	// Get package versions (tags)
	versions, _, err := client.Organizations.PackageGetAllVersions(ctx, owner, "container", targetPackage.GetName(), &github.PackageListOptions{
		State: github.String("active"),
	})
	if err != nil || len(versions) == 0 {
		log.Trace().Str("repository", repo.GetFullName()).Msg("No package versions found")
		return nil
	}

	// Find the most recent version
	var mostRecentVersion *github.PackageVersion
	for _, ver := range versions {
		if ver.GetCreatedAt().Time.After(mostRecentVersion.GetCreatedAt().Time) || mostRecentVersion == nil {
			mostRecentVersion = ver
		}
	}

	if mostRecentVersion == nil {
		return nil
	}

	metadata := &RegistryMetadata{
		TagName: extractTag(mostRecentVersion),
	}

	if !mostRecentVersion.GetCreatedAt().IsZero() {
		metadata.LastUpdate = mostRecentVersion.GetCreatedAt().Format("2006-01-02T15:04:05Z07:00")
	}

	log.Trace().
		Str("repository", repo.GetFullName()).
		Str("tag_name", metadata.TagName).
		Str("last_update", metadata.LastUpdate).
		Msg("Tag details from API")

	log.Debug().
		Str("repository", repo.GetFullName()).
		Str("package", targetPackage.GetName()).
		Str("tag", metadata.TagName).
		Msg("Fetched registry metadata")

	return metadata
}

func extractTag(version *github.PackageVersion) string {
	if len(version.Metadata.Container.Tags) > 0 {
		return version.Metadata.Container.Tags[0]
	}
	// Fallback to version name
	return version.GetName()
}
