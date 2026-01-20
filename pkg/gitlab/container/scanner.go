package container

import (
	"encoding/base64"
	"regexp"
	"strings"

	"github.com/CompassSecurity/pipeleek/pkg/gitlab/util"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// RunScan performs the container scan with the given options
func RunScan(opts ScanOptions) {
	git, err := util.GetGitlabClient(opts.GitlabApiToken, opts.GitlabUrl)
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Failed creating gitlab client")
	}

	validateOrderBy(opts.OrderBy)

	patterns := DefaultPatterns()
	log.Info().Int("pattern_count", len(patterns)).Msg("Loaded container scan patterns")

	if opts.Repository != "" {
		scanSingleProject(git, opts.Repository, patterns, opts)
	} else if opts.Namespace != "" {
		scanNamespace(git, opts.Namespace, patterns, opts)
	} else {
		fetchProjects(git, patterns, opts)
	}

	log.Info().Msg("Container scan complete")
}

func scanSingleProject(git *gitlab.Client, projectName string, patterns []Pattern, opts ScanOptions) {
	log.Info().Str("repository", projectName).Msg("Scanning specific repository for dangerous container patterns")
	project, resp, err := git.Projects.GetProject(projectName, &gitlab.GetProjectOptions{})
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Failed fetching project by repository name")
	}
	if resp.StatusCode == 404 {
		log.Fatal().Msg("Project not found")
	}
	scanProject(git, project, patterns)
}

func scanNamespace(git *gitlab.Client, namespace string, patterns []Pattern, opts ScanOptions) {
	log.Info().Str("namespace", namespace).Msg("Scanning specific namespace for dangerous container patterns")
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
		scanProject(git, project, patterns)
		return nil
	})
	if err != nil {
		log.Error().Stack().Err(err).Msg("Failed iterating group projects")
		return
	}

	log.Info().Msg("Fetched all namespace projects")
}

func fetchProjects(git *gitlab.Client, patterns []Pattern, opts ScanOptions) {
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
		scanProject(git, project, patterns)
		return nil
	})
	if err != nil {
		log.Error().Stack().Err(err).Msg("Failed iterating projects")
		return
	}

	log.Info().Msg("Fetched all projects")
}

func scanProject(git *gitlab.Client, project *gitlab.Project, patterns []Pattern) {
	log.Debug().Str("project", project.PathWithNamespace).Msg("Scanning project for Dockerfiles")

	// Find all Dockerfiles in the project recursively
	dockerfiles := findDockerfiles(git, project)

	if len(dockerfiles) == 0 {
		log.Trace().Str("project", project.PathWithNamespace).Msg("No Dockerfile or Containerfile found")
		return
	}

	log.Debug().Str("project", project.PathWithNamespace).Int("dockerfile_count", len(dockerfiles)).Msg("Found Dockerfiles")

	// Check for .dockerignore once per project
	hasDockerignore := checkDockerignoreExists(git, project)

	// Scan all found Dockerfiles
	for _, dockerfile := range dockerfiles {
		isMultistage := checkIsMultistage(dockerfile)
		scanDockerfile(git, project, dockerfile, dockerfile.FileName, patterns, hasDockerignore, isMultistage)
	}
}

// findDockerfiles recursively searches for all Dockerfile/Containerfile files in the project
func findDockerfiles(git *gitlab.Client, project *gitlab.Project) []*gitlab.File {
	const maxDockerfiles = 50 // Limit to prevent scanning huge repos
	
	dockerfileNames := map[string]bool{
		"Dockerfile":   true,
		"Containerfile": true,
		"dockerfile":   true,
		"containerfile": true,
	}
	
	var dockerfiles []*gitlab.File
	var queue []string
	queue = append(queue, "") // Start with root directory
	visited := make(map[string]bool)
	
	for len(queue) > 0 && len(dockerfiles) < maxDockerfiles {
		path := queue[0]
		queue = queue[1:]
		
		if visited[path] {
			continue
		}
		visited[path] = true
		
		// List contents of current directory using tree API
		treeOpts := &gitlab.ListTreeOptions{
			Path: gitlab.Ptr(path),
			ListOptions: gitlab.ListOptions{
				PerPage: 100,
				Page:    1,
			},
		}
		
		for {
			tree, resp, err := git.Repositories.ListTree(project.ID, treeOpts)
			if err != nil {
				log.Trace().Str("project", project.PathWithNamespace).Str("path", path).Err(err).Msg("Error listing directory")
				break
			}
			
			if resp == nil {
				break
			}
			
			for _, node := range tree {
				if len(dockerfiles) >= maxDockerfiles {
					return dockerfiles
				}
				
				// Check if it's a file (blob) and matches a Dockerfile name
				if node.Type == "blob" {
					// Get just the filename from the path
					parts := strings.Split(node.Path, "/")
					fileName := parts[len(parts)-1]
					
					if dockerfileNames[fileName] {
						// Fetch the file content
						file, resp, err := git.RepositoryFiles.GetFile(project.ID, node.Path, &gitlab.GetFileOptions{Ref: gitlab.Ptr("HEAD")})
						if err != nil || resp.StatusCode != 200 {
							log.Trace().Str("project", project.PathWithNamespace).Str("file", node.Path).Err(err).Msg("Error fetching Dockerfile")
							continue
						}
						
						// Store the path in FileName field
						file.FileName = node.Path
						dockerfiles = append(dockerfiles, file)
					}
				} else if node.Type == "tree" {
					// Add directory to queue for recursive search
					queue = append(queue, node.Path)
				}
			}
			
			// Check if there are more pages
			if resp.NextPage == 0 {
				break
			}
			treeOpts.Page = resp.NextPage
		}
	}
	
	return dockerfiles
}

// checkDockerignoreExists checks if a .dockerignore file exists in the repository
func checkDockerignoreExists(git *gitlab.Client, project *gitlab.Project) bool {
	_, resp, err := git.RepositoryFiles.GetFile(project.ID, ".dockerignore", &gitlab.GetFileOptions{Ref: gitlab.Ptr("HEAD")})
	if err != nil || resp.StatusCode == 404 {
		return false
	}
	return resp.StatusCode == 200
}

// checkIsMultistage checks if the Dockerfile uses multistage builds by counting FROM statements
func checkIsMultistage(file *gitlab.File) bool {
	// Decode the file content
	decodedContent, err := base64.StdEncoding.DecodeString(file.Content)
	if err != nil {
		return false
	}

	content := string(decodedContent)
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

func scanDockerfile(git *gitlab.Client, project *gitlab.Project, file *gitlab.File, fileName string, patterns []Pattern, hasDockerignore bool, isMultistage bool) {
	log.Debug().Str("project", project.PathWithNamespace).Str("file", fileName).Msg("Scanning Dockerfile")

	// The GitLab API returns file content as base64 encoded
	decodedContent, err := base64.StdEncoding.DecodeString(file.Content)
	if err != nil {
		log.Error().Str("project", project.PathWithNamespace).Str("file", fileName).Err(err).Msg("Failed to decode file content")
		return
	}

	content := string(decodedContent)
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
				ProjectPath:     project.PathWithNamespace,
				ProjectURL:      project.WebURL,
				FilePath:        fileName,
				FileName:        fileName,
				MatchedPattern:  pattern.Name,
				LineContent:     matchedLine,
				PatternSeverity: pattern.Severity,
				HasDockerignore: hasDockerignore,
				IsMultistage:    isMultistage,
			}

			// Fetch registry metadata for the most recent container
			finding.RegistryMetadata = fetchRegistryMetadata(git, project)

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

// fetchRegistryMetadata retrieves metadata about the most recent container image in the project's registry
func fetchRegistryMetadata(git *gitlab.Client, project *gitlab.Project) *RegistryMetadata {
	// List container repositories for the project
	repos, resp, err := git.ContainerRegistry.ListProjectRegistryRepositories(project.ID, &gitlab.ListProjectRegistryRepositoriesOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: 10,
			Page:    1,
		},
	})
	if err != nil {
		log.Trace().Str("project", project.PathWithNamespace).Err(err).Msg("Error accessing container registry")
		return nil
	}
	if resp != nil && resp.StatusCode != 200 {
		log.Trace().Str("project", project.PathWithNamespace).Int("status", resp.StatusCode).Msg("Container registry not accessible")
		return nil
	}

	if len(repos) == 0 {
		log.Trace().Str("project", project.PathWithNamespace).Msg("No container repositories found in registry")
		return nil
	}

	// Get the first repository (most recent activity)
	repo := repos[0]

	// List tags for this repository
	tags, resp, err := git.ContainerRegistry.ListRegistryRepositoryTags(project.ID, repo.ID, &gitlab.ListRegistryRepositoryTagsOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: 100,
			Page:    1,
		},
	})
	if err != nil || resp.StatusCode != 200 || len(tags) == 0 {
		log.Trace().Str("project", project.PathWithNamespace).Str("repo", repo.Path).Msg("No tags found in registry repository")
		return nil
	}

	// Get detailed information for each tag and find the most recent one
	var mostRecentTag *gitlab.RegistryRepositoryTag
	for _, t := range tags {
		// Get detailed tag information
		tagDetails, resp, err := git.ContainerRegistry.GetRegistryRepositoryTagDetail(project.ID, repo.ID, t.Name)
		if err != nil || resp.StatusCode != 200 {
			log.Trace().Str("tag", t.Name).Msg("Could not get tag details")
			continue
		}

		if tagDetails.CreatedAt != nil {
			if mostRecentTag == nil || (mostRecentTag.CreatedAt != nil && tagDetails.CreatedAt.After(*mostRecentTag.CreatedAt)) {
				mostRecentTag = tagDetails
			}
		}
	}

	if mostRecentTag == nil {
		log.Trace().Str("project", project.PathWithNamespace).Str("repo", repo.Path).Msg("No tags with timestamps found")
		return nil
	}

	metadata := &RegistryMetadata{
		TagName: mostRecentTag.Name,
	}

	// Format the timestamp
	if mostRecentTag.CreatedAt != nil {
		metadata.LastUpdate = mostRecentTag.CreatedAt.Format("2006-01-02T15:04:05Z07:00")
	}

	log.Trace().
		Str("project", project.PathWithNamespace).
		Str("tag_name", mostRecentTag.Name).
		Str("last_update", metadata.LastUpdate).
		Msg("Tag details from API")

	log.Debug().
		Str("project", project.PathWithNamespace).
		Str("repo", repo.Path).
		Str("tag", mostRecentTag.Name).
		Msg("Fetched registry metadata")

	return metadata
}

func validateOrderBy(orderBy string) {
	validValues := map[string]bool{
		"id": true, "name": true, "path": true, "created_at": true,
		"updated_at": true, "star_count": true, "last_activity_at": true, "similarity": true,
	}
	if !validValues[orderBy] {
		log.Fatal().Str("order_by", orderBy).Msg("Invalid order-by value")
	}
}
