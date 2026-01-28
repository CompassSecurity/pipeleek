package container

import (
	"context"
	"strings"

	sharedcontainer "github.com/CompassSecurity/pipeleek/pkg/container"
	"github.com/google/go-github/v69/github"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// RunScan performs the container scan with the given options
func RunScan(opts ScanOptions, client *github.Client) {
	ctx := context.Background()

	patterns := sharedcontainer.DefaultPatterns()
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

func scanSingleRepo(ctx context.Context, client *github.Client, repoName string, patterns []sharedcontainer.Pattern) {
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

func scanOrganization(ctx context.Context, client *github.Client, orgName string, patterns []sharedcontainer.Pattern, opts ScanOptions) {
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

func fetchRepositories(ctx context.Context, client *github.Client, patterns []sharedcontainer.Pattern, opts ScanOptions) {
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

	// Add public filter if requested
	if opts.Public {
		if query != "" {
			query += " is:public"
		} else {
			query = "is:public"
		}
	}

	if query == "" {
		log.Fatal().Msg("No search criteria specified. Use --owned, --member, --public, --org, --repo, or --search")
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

func scanRepository(ctx context.Context, client *github.Client, repo *github.Repository, patterns []sharedcontainer.Pattern) {
	log.Debug().Str("repository", repo.GetFullName()).Msg("Scanning repository for Dockerfiles")

	owner := repo.GetOwner().GetLogin()
	repoName := repo.GetName()

	// Find all Dockerfiles in the repository recursively
	dockerfiles := findDockerfiles(ctx, client, owner, repoName)

	if len(dockerfiles) == 0 {
		log.Trace().Str("repository", repo.GetFullName()).Msg("No Dockerfile or Containerfile found")
		return
	}

	log.Debug().Str("repository", repo.GetFullName()).Int("dockerfile_count", len(dockerfiles)).Msg("Found Dockerfiles")

	// Scan all found Dockerfiles
	for _, dockerfile := range dockerfiles {
		isMultistage := checkIsMultistage(dockerfile.Content)
		scanDockerfile(ctx, client, repo, dockerfile.Content, dockerfile.Path, patterns, isMultistage)
	}
}

// DockerfileMatch represents a found Dockerfile
type DockerfileMatch struct {
	Path    string
	Content *github.RepositoryContent
}

// findDockerfiles recursively searches for all Dockerfile/Containerfile files in the repository
func findDockerfiles(ctx context.Context, client *github.Client, owner, repo string) []DockerfileMatch {
	var dockerfiles []DockerfileMatch
	const maxDockerfiles = 50 // Limit to prevent scanning huge repos

	dockerfileNames := []string{"Dockerfile", "Containerfile", "dockerfile", "containerfile"}

	// Use GitHub Search API to find files matching Dockerfile patterns
	for _, name := range dockerfileNames {
		if len(dockerfiles) >= maxDockerfiles {
			break
		}

		// Search for this filename in the repository
		query := strings.Join([]string{
			"repo:" + owner + "/" + repo,
			"filename:" + name,
		}, " ")

		results, _, err := client.Search.Code(ctx, query, &github.SearchOptions{
			ListOptions: github.ListOptions{
				PerPage: 50,
				Page:    1,
			},
		})
		if err != nil {
			log.Trace().Str("repository", owner+"/"+repo).Str("filename", name).Err(err).Msg("Error searching for Dockerfile")
			continue
		}

		if results.GetTotal() == 0 {
			continue
		}

		// Fetch each found file's content
		for _, result := range results.CodeResults {
			if len(dockerfiles) >= maxDockerfiles {
				break
			}

			path := result.GetPath()
			fileContent, _, _, err := client.Repositories.GetContents(ctx, owner, repo, path, nil)
			if err != nil {
				log.Trace().Str("repository", owner+"/"+repo).Str("file", path).Err(err).Msg("Error fetching Dockerfile content")
				continue
			}

			if fileContent != nil {
				dockerfiles = append(dockerfiles, DockerfileMatch{
					Path:    path,
					Content: fileContent,
				})
			}
		}
	}

	return dockerfiles
}

// checkIsMultistage checks if the Dockerfile uses multistage builds
func checkIsMultistage(fileContent *github.RepositoryContent) bool {
	content, err := fileContent.GetContent()
	if err != nil {
		return false
	}

	return sharedcontainer.IsMultistage(content)

}

func scanDockerfile(ctx context.Context, client *github.Client, repo *github.Repository, fileContent *github.RepositoryContent, fileName string, patterns []sharedcontainer.Pattern, isMultistage bool) {
	log.Debug().Str("repository", repo.GetFullName()).Str("file", fileName).Msg("Scanning Dockerfile")

	content, err := fileContent.GetContent()
	if err != nil {
		log.Error().Str("repository", repo.GetFullName()).Str("file", fileName).Err(err).Msg("Failed to get file content")
		return
	}

	// Use shared scanner to find pattern matches
	matches := sharedcontainer.ScanDockerfileForPatterns(content, patterns)

	for _, match := range matches {
		finding := sharedcontainer.Finding{
			ProjectPath:    repo.GetFullName(),
			ProjectURL:     repo.GetHTMLURL(),
			FilePath:       fileName,
			FileName:       fileName,
			MatchedPattern: match.PatternName,
			LineContent:    match.MatchedLine,
			IsMultistage:   isMultistage,
		}

		// Fetch registry metadata for the most recent container
		finding.RegistryMetadata = fetchRegistryMetadata(ctx, client, repo)

		logFinding(finding)
	}
}

func logFinding(finding sharedcontainer.Finding) {
	logEvent := log.WithLevel(zerolog.InfoLevel).
		Str("url", finding.ProjectURL).
		Str("file", finding.FilePath).
		Str("content", finding.LineContent).
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
func fetchRegistryMetadata(ctx context.Context, client *github.Client, repo *github.Repository) *sharedcontainer.RegistryMetadata {
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

	metadata := &sharedcontainer.RegistryMetadata{
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
