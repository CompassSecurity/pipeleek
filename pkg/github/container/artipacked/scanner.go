package artipacked

import (
	"context"
	"strings"

	sharedcontainer "github.com/CompassSecurity/pipeleek/pkg/container"
	"github.com/google/go-github/v69/github"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

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
		if opts.Owned {
			query = "user:@me"
		} else if opts.Member {
			query = "user:@me"
		}
	}

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

	dockerfiles := findDockerfiles(ctx, client, owner, repoName)

	if len(dockerfiles) == 0 {
		log.Trace().Str("repository", repo.GetFullName()).Msg("No Dockerfile or Containerfile found")
		return
	}

	log.Debug().Str("repository", repo.GetFullName()).Int("dockerfile_count", len(dockerfiles)).Msg("Found Dockerfiles")

	for _, dockerfile := range dockerfiles {
		isMultistage := checkIsMultistage(dockerfile.Content)
		scanDockerfile(ctx, client, repo, dockerfile.Content, dockerfile.Path, patterns, isMultistage)
	}
}

type DockerfileMatch struct {
	Path    string
	Content *github.RepositoryContent
}

func findDockerfiles(ctx context.Context, client *github.Client, owner, repo string) []DockerfileMatch {
	var dockerfiles []DockerfileMatch
	const maxDockerfiles = 50 // Limit to prevent scanning huge repos

	defaultBranch := "HEAD"
	repository, _, err := client.Repositories.Get(ctx, owner, repo)
	if err == nil && repository != nil && repository.GetDefaultBranch() != "" {
		defaultBranch = repository.GetDefaultBranch()
	}

	tree, _, err := client.Git.GetTree(ctx, owner, repo, defaultBranch, true)
	if err != nil {
		log.Trace().Str("repository", owner+"/"+repo).Err(err).Msg("Error listing repository tree")
		return dockerfiles
	}

	if tree == nil || len(tree.Entries) == 0 {
		return dockerfiles
	}

	if tree.GetTruncated() {
		log.Trace().Str("repository", owner+"/"+repo).Msg("Repository tree response truncated")
	}

	isDockerfileName := map[string]bool{
		"Dockerfile":    true,
		"Containerfile": true,
		"dockerfile":    true,
		"containerfile": true,
	}

	for _, entry := range tree.Entries {
		if len(dockerfiles) >= maxDockerfiles {
			break
		}

		if entry.GetType() != "blob" {
			continue
		}

		path := entry.GetPath()
		if path == "" {
			continue
		}

		pathParts := strings.Split(path, "/")
		fileName := pathParts[len(pathParts)-1]
		if !isDockerfileName[fileName] {
			continue
		}

		fileContent, _, _, getErr := client.Repositories.GetContents(ctx, owner, repo, path, nil)
		if getErr != nil {
			log.Trace().Str("repository", owner+"/"+repo).Str("file", path).Err(getErr).Msg("Error fetching Dockerfile content")
			continue
		}

		if fileContent == nil {
			continue
		}

		dockerfiles = append(dockerfiles, DockerfileMatch{
			Path:    path,
			Content: fileContent,
		})
	}

	return dockerfiles
}

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

	matches := sharedcontainer.ScanDockerfileForPatterns(content, patterns)
	if len(matches) == 0 {
		return
	}

	latestCIRunAt := fetchLatestWorkflowRunAt(ctx, client, repo)
	registryMetadata := fetchRegistryMetadata(ctx, client, repo)

	for _, match := range matches {
		finding := sharedcontainer.Finding{
			ProjectPath:      repo.GetFullName(),
			ProjectURL:       repo.GetHTMLURL(),
			FilePath:         fileName,
			FileName:         fileName,
			MatchedPattern:   match.PatternName,
			LineContent:      match.MatchedLine,
			IsMultistage:     isMultistage,
			LatestCIRunAt:    latestCIRunAt,
			RegistryMetadata: registryMetadata,
		}

		logFinding(finding)
	}
}

func logFinding(finding sharedcontainer.Finding) {
	logEvent := log.WithLevel(zerolog.InfoLevel).
		Str("url", finding.ProjectURL).
		Str("file", finding.FilePath).
		Str("content", finding.LineContent).
		Bool("is_multistage", finding.IsMultistage)

	if finding.LatestCIRunAt != "" {
		logEvent = logEvent.Str("latest_ci_run_at", finding.LatestCIRunAt)
	}

	if finding.RegistryMetadata != nil {
		logEvent = logEvent.Str("registry_tag", finding.RegistryMetadata.TagName)

		if finding.RegistryMetadata.LastUpdate != "" {
			logEvent = logEvent.Str("registry_last_update", finding.RegistryMetadata.LastUpdate)
		}
	}

	logEvent.Msg("Identified")
}

func fetchLatestWorkflowRunAt(ctx context.Context, client *github.Client, repo *github.Repository) string {
	owner := repo.GetOwner().GetLogin()
	repoName := repo.GetName()

	runs, _, err := client.Actions.ListRepositoryWorkflowRuns(ctx, owner, repoName, &github.ListWorkflowRunsOptions{
		ListOptions: github.ListOptions{
			PerPage: 1,
			Page:    1,
		},
	})
	if err != nil {
		log.Trace().Str("repository", repo.GetFullName()).Err(err).Msg("Error fetching latest workflow run")
		return ""
	}

	if runs == nil || len(runs.WorkflowRuns) == 0 {
		log.Trace().Str("repository", repo.GetFullName()).Msg("No workflow runs found")
		return ""
	}

	latestRun := runs.WorkflowRuns[0]
	runDate := latestRun.UpdatedAt
	if runDate == nil {
		runDate = latestRun.RunStartedAt
	}
	if runDate == nil {
		runDate = latestRun.CreatedAt
	}
	if runDate == nil {
		log.Trace().Str("repository", repo.GetFullName()).Int64("run_id", latestRun.GetID()).Msg("Latest workflow run has no timestamp")
		return ""
	}

	formattedDate := sharedcontainer.FormatFindingDate(runDate.Time)

	log.Debug().
		Str("repository", repo.GetFullName()).
		Int64("run_id", latestRun.GetID()).
		Str("latest_ci_run_at", formattedDate).
		Msg("Fetched latest workflow metadata")

	return formattedDate
}

func fetchRegistryMetadata(ctx context.Context, client *github.Client, repo *github.Repository) *sharedcontainer.RegistryMetadata {
	owner := repo.GetOwner().GetLogin()
	repoName := repo.GetName()

	packages, _, err := client.Organizations.ListPackages(ctx, owner, &github.PackageListOptions{
		PackageType: github.Ptr("container"),
	})
	if err != nil {
		log.Trace().Str("repository", repo.GetFullName()).Err(err).Msg("Error accessing container registry")
		return nil
	}

	if len(packages) == 0 {
		log.Trace().Str("repository", repo.GetFullName()).Msg("No container packages found in registry")
		return nil
	}

	var targetPackage *github.Package
	for _, pkg := range packages {
		if strings.Contains(strings.ToLower(pkg.GetName()), strings.ToLower(repoName)) {
			targetPackage = pkg
			break
		}
	}

	if targetPackage == nil {
		targetPackage = packages[0]
	}

	versions, _, err := client.Organizations.PackageGetAllVersions(ctx, owner, "container", targetPackage.GetName(), &github.PackageListOptions{
		State: github.Ptr("active"),
	})
	if err != nil || len(versions) == 0 {
		log.Trace().Str("repository", repo.GetFullName()).Msg("No package versions found")
		return nil
	}

	var mostRecentVersion *github.PackageVersion
	for _, ver := range versions {
		if mostRecentVersion == nil || ver.GetCreatedAt().Time.After(mostRecentVersion.GetCreatedAt().Time) {
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
		formattedDate := sharedcontainer.FormatFindingDate(mostRecentVersion.GetCreatedAt().Time)
		metadata.LastUpdate = formattedDate
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
	return version.GetName()
}
