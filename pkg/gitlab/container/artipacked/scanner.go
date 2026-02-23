package artipacked

import (
	"encoding/base64"
	"strings"
	"time"

	sharedcontainer "github.com/CompassSecurity/pipeleek/pkg/container"
	"github.com/CompassSecurity/pipeleek/pkg/gitlab/util"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func RunScan(opts ScanOptions) {
	git, err := util.GetGitlabClient(opts.GitlabApiToken, opts.GitlabUrl)
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Failed creating gitlab client")
	}

	validateOrderBy(opts.OrderBy)

	patterns := sharedcontainer.DefaultPatterns()
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

func scanSingleProject(git *gitlab.Client, projectName string, patterns []sharedcontainer.Pattern, opts ScanOptions) {
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

func scanNamespace(git *gitlab.Client, namespace string, patterns []sharedcontainer.Pattern, opts ScanOptions) {
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

func fetchProjects(git *gitlab.Client, patterns []sharedcontainer.Pattern, opts ScanOptions) {
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

func scanProject(git *gitlab.Client, project *gitlab.Project, patterns []sharedcontainer.Pattern) {
	log.Debug().Str("project", project.PathWithNamespace).Msg("Scanning project for Dockerfiles")

	dockerfiles := findDockerfiles(git, project)

	if len(dockerfiles) == 0 {
		log.Trace().Str("project", project.PathWithNamespace).Msg("No Dockerfile or Containerfile found")
		return
	}

	log.Debug().Str("project", project.PathWithNamespace).Int("dockerfile_count", len(dockerfiles)).Msg("Found Dockerfiles")

	for _, dockerfile := range dockerfiles {
		isMultistage := checkIsMultistage(dockerfile)
		scanDockerfile(git, project, dockerfile, dockerfile.FileName, patterns, isMultistage)
	}
}

func findDockerfiles(git *gitlab.Client, project *gitlab.Project) []*gitlab.File {
	const maxDockerfiles = 50 // Limit to prevent scanning huge repos
	const maxDepth = 2        // Only search up to 2 levels deep (root and 1 subfolder level)

	dockerfileNames := map[string]bool{
		"Dockerfile":    true,
		"Containerfile": true,
		"dockerfile":    true,
		"containerfile": true,
	}

	startTime := time.Now()

	var dockerfiles []*gitlab.File

	treeOpts := &gitlab.ListTreeOptions{
		Recursive: gitlab.Ptr(true),
		ListOptions: gitlab.ListOptions{
			PerPage: 100,
			Page:    1,
		},
	}

	tree, resp, err := git.Repositories.ListTree(project.ID, treeOpts)
	if err != nil {
		log.Trace().Str("project", project.PathWithNamespace).Err(err).Msg("Error listing recursive tree")
		return dockerfiles
	}

	if resp == nil || len(tree) == 0 {
		log.Trace().Str("project", project.PathWithNamespace).Msg("No files found in tree")
		return dockerfiles
	}

	for _, node := range tree {
		if len(dockerfiles) >= maxDockerfiles {
			break
		}

		if node.Type != "blob" {
			continue
		}

		depth := strings.Count(node.Path, "/")
		if depth > maxDepth-1 {
			continue // Skip files deeper than maxDepth levels
		}

		parts := strings.Split(node.Path, "/")
		fileName := parts[len(parts)-1]

		if dockerfileNames[fileName] {
			file, resp, err := git.RepositoryFiles.GetFile(project.ID, node.Path, &gitlab.GetFileOptions{Ref: gitlab.Ptr("HEAD")})
			if err != nil || resp.StatusCode != 200 {
				log.Trace().Str("project", project.PathWithNamespace).Str("file", node.Path).Err(err).Msg("Error fetching Dockerfile")
				continue
			}

			file.FileName = node.Path
			dockerfiles = append(dockerfiles, file)
			log.Trace().Str("project", project.PathWithNamespace).Str("file", node.Path).Msg("Found Dockerfile")
		}
	}

	elapsed := time.Since(startTime)
	log.Debug().Str("project", project.PathWithNamespace).Int("found", len(dockerfiles)).Dur("elapsed_ms", elapsed).Msg("Dockerfile search complete")
	return dockerfiles
}

func checkIsMultistage(file *gitlab.File) bool {
	decodedContent, err := base64.StdEncoding.DecodeString(file.Content)
	if err != nil {
		return false
	}

	return sharedcontainer.IsMultistage(string(decodedContent))
}

func scanDockerfile(git *gitlab.Client, project *gitlab.Project, file *gitlab.File, fileName string, patterns []sharedcontainer.Pattern, isMultistage bool) {
	log.Debug().Str("project", project.PathWithNamespace).Str("file", fileName).Msg("Scanning Dockerfile")

	decodedContent, err := base64.StdEncoding.DecodeString(file.Content)
	if err != nil {
		log.Error().Str("project", project.PathWithNamespace).Str("file", fileName).Err(err).Msg("Failed to decode file content")
		return
	}

	content := string(decodedContent)

	matches := sharedcontainer.ScanDockerfileForPatterns(content, patterns)
	if len(matches) == 0 {
		return
	}

	latestCIRunAt := fetchLatestPipelineRunAt(git, project)
	registryMetadata := fetchRegistryMetadata(git, project)

	for _, match := range matches {
		finding := sharedcontainer.Finding{
			ProjectPath:      project.PathWithNamespace,
			ProjectURL:       project.WebURL,
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

func fetchLatestPipelineRunAt(git *gitlab.Client, project *gitlab.Project) string {
	startTime := time.Now()

	pipelines, resp, err := git.Pipelines.ListProjectPipelines(project.ID, &gitlab.ListProjectPipelinesOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: 1,
			Page:    1,
		},
		OrderBy: gitlab.Ptr("updated_at"),
		Sort:    gitlab.Ptr("desc"),
	})
	if err != nil {
		log.Trace().Str("project", project.PathWithNamespace).Err(err).Msg("Error fetching latest project pipeline")
		return ""
	}
	if resp != nil && resp.StatusCode != 200 {
		log.Trace().Str("project", project.PathWithNamespace).Int("status", resp.StatusCode).Msg("Pipeline endpoint not accessible")
		return ""
	}
	if len(pipelines) == 0 {
		log.Trace().Str("project", project.PathWithNamespace).Msg("No pipelines found")
		return ""
	}

	latestPipeline := pipelines[0]
	pipelineDate := latestPipeline.UpdatedAt
	if pipelineDate == nil {
		pipelineDate = latestPipeline.CreatedAt
	}
	if pipelineDate == nil {
		log.Trace().Str("project", project.PathWithNamespace).Int64("pipeline_id", latestPipeline.ID).Msg("Latest pipeline has no timestamp")
		return ""
	}

	formattedDate := sharedcontainer.FormatFindingDate(*pipelineDate)

	elapsed := time.Since(startTime)
	log.Debug().
		Str("project", project.PathWithNamespace).
		Int64("pipeline_id", latestPipeline.ID).
		Str("latest_ci_run_at", formattedDate).
		Dur("elapsed_ms", elapsed).
		Msg("Fetched latest pipeline metadata")

	return formattedDate
}

func fetchRegistryMetadata(git *gitlab.Client, project *gitlab.Project) *sharedcontainer.RegistryMetadata {
	startTime := time.Now()

	repos, resp, err := git.ContainerRegistry.ListProjectRegistryRepositories(project.ID, &gitlab.ListProjectRegistryRepositoriesOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: 100,
			Page:    1,
		},
		TagsCount: gitlab.Ptr(true),
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

	var newestTag *gitlab.RegistryRepositoryTag
	newestTagRepoPath := ""
	fallbackTagName := ""
	fallbackTagRepoPath := ""

	for _, repo := range repos {
		if repo.TagsCount == 0 {
			continue
		}

		tagOpts := &gitlab.ListRegistryRepositoryTagsOptions{
			ListOptions: gitlab.ListOptions{
				PerPage: 100,
				Page:    1,
			},
		}

		for {
			tags, tagsResp, tagsErr := git.ContainerRegistry.ListRegistryRepositoryTags(project.ID, repo.ID, tagOpts)
			if tagsErr != nil {
				log.Trace().Str("project", project.PathWithNamespace).Str("repo", repo.Path).Err(tagsErr).Msg("Error listing registry tags")
				break
			}
			if tagsResp != nil && tagsResp.StatusCode != 200 {
				log.Trace().Str("project", project.PathWithNamespace).Str("repo", repo.Path).Int("status", tagsResp.StatusCode).Msg("Failed listing registry tags")
				break
			}
			if len(tags) == 0 {
				break
			}

			for _, tag := range tags {
				if fallbackTagName == "" {
					fallbackTagName = tag.Name
					fallbackTagRepoPath = repo.Path
				}

				tagDetail := tag
				if tagDetail.CreatedAt == nil {
					detail, detailResp, detailErr := git.ContainerRegistry.GetRegistryRepositoryTagDetail(project.ID, repo.ID, tag.Name)
					if detailErr != nil {
						log.Trace().Str("project", project.PathWithNamespace).Str("repo", repo.Path).Str("tag", tag.Name).Err(detailErr).Msg("Error fetching registry tag detail")
						continue
					}
					if detailResp != nil && detailResp.StatusCode != 200 {
						log.Trace().Str("project", project.PathWithNamespace).Str("repo", repo.Path).Str("tag", tag.Name).Int("status", detailResp.StatusCode).Msg("Registry tag detail not accessible")
						continue
					}
					tagDetail = detail
				}

				if tagDetail == nil || tagDetail.CreatedAt == nil {
					continue
				}

				if newestTag == nil || tagDetail.CreatedAt.After(*newestTag.CreatedAt) {
					newestTag = tagDetail
					newestTagRepoPath = repo.Path
				}
			}

			if tagsResp == nil || tagsResp.NextPage == 0 {
				break
			}

			tagOpts.Page = tagsResp.NextPage
		}
	}

	if newestTag == nil {
		if fallbackTagName == "" {
			log.Trace().Str("project", project.PathWithNamespace).Msg("No tags found in any registry repository")
			return nil
		}

		elapsed := time.Since(startTime)
		log.Debug().
			Str("project", project.PathWithNamespace).
			Str("repo", fallbackTagRepoPath).
			Str("tag", fallbackTagName).
			Dur("elapsed_ms", elapsed).
			Msg("Fetched registry metadata without tag creation timestamp")

		return &sharedcontainer.RegistryMetadata{TagName: fallbackTagName}
	}

	formattedDate := sharedcontainer.FormatFindingDate(*newestTag.CreatedAt)
	metadata := &sharedcontainer.RegistryMetadata{
		TagName:    newestTag.Name,
		LastUpdate: formattedDate,
	}

	elapsed := time.Since(startTime)
	log.Debug().
		Str("project", project.PathWithNamespace).
		Str("repo", newestTagRepoPath).
		Str("tag", newestTag.Name).
		Str("last_update", metadata.LastUpdate).
		Dur("elapsed_ms", elapsed).
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
