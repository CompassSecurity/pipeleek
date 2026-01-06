package lab

import (
	"context"
	"fmt"
	"time"

	"github.com/google/go-github/v69/github"
	"github.com/rs/zerolog/log"
)

// renovateConfigWithAutodiscovery is a renovate.json config that enables autodiscovery
var renovateConfigWithAutodiscovery = `{
  "extends": ["config:base"],
  "autodiscover": true,
  "autodiscoverFilter": ["**"],
  "onboarding": false,
  "requireConfig": false,
  "semanticCommits": "enabled",
  "commitMessagePrefix": "[Renovate] "
}
`

// renovateWorkflowYml is a GitHub Actions workflow that runs Renovate with autodiscovery
var renovateWorkflowYml = `name: Renovate

on:
  schedule:
    - cron: '0 0 * * *'
  workflow_dispatch:
  push:
    branches:
      - main

concurrency:
  group: renovate
  cancel-in-progress: false

jobs:
  renovate:
    runs-on: ubuntu-latest
    if: github.repository_owner == github.actor || github.event_name == 'workflow_dispatch'
    permissions:
      contents: write
      pull-requests: write
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Self-hosted Renovate
        uses: renovatebot/github-action@v40.3.10
        with:
          token: ${{ secrets.RENOVATE_LAB_TOKEN }}
        env:
          LOG_LEVEL: debug
          RENOVATE_LOG_LEVEL: debug
          RENOVATE_ONBOARDING_CONFIG_FILE_NAME: renovate.json
          RENOVATE_EXTENDS: config:base
          RENOVATE_AUTODISCOVER: 'true'
          RENOVATE_AUTODISCOVER_FILTER: '**'
          DEBUG: 'renovate:*'

      - name: Validate exploit execution
        if: always()
        run: |
          echo "=== Renovate Lab Setup - Exploit Validation ==="
          if [ -f /tmp/pipeleek-exploit-executed.txt ]; then
            echo "✓ SUCCESS: Exploit was executed by Renovate!"
            echo "=== Exploit proof file contents ==="
            cat /tmp/pipeleek-exploit-executed.txt
          else
            echo "ℹ Exploit not executed yet (may require Renovate Bot to process dependencies)"
            echo "This is expected on first run - Renovate needs to scan for updates"
          fi
`

// LabSetupConfig contains configuration for lab setup
type LabSetupConfig struct {
	RepoName string
	Owner    string
}

// RunLabSetup creates a GitHub repository with Renovate autodiscovery configuration
func RunLabSetup(client *github.Client, repoName, owner string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	log.Info().
		Str("repo", repoName).
		Str("owner", owner).
		Msg("Starting Renovate Lab setup")

	// Create the repository
	repo := &github.Repository{
		Name:        github.Ptr(repoName),
		Description: github.Ptr("Renovate Lab - Testing autodiscovery with dependency updates"),
		Private:     github.Ptr(false),
		AutoInit:    github.Ptr(true),
	}

	createdRepo, _, err := client.Repositories.Create(ctx, "", repo)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create repository")
		return fmt.Errorf("failed to create repository: %w", err)
	}

	log.Info().
		Str("url", createdRepo.GetHTMLURL()).
		Msg("Repository created successfully")

	// Add renovate.json configuration file
	log.Debug().Msg("Adding renovate.json configuration")
	renovateFileOpts := &github.RepositoryContentFileOptions{
		Message: github.Ptr("ci: Add Renovate configuration with autodiscovery enabled"),
		Content: []byte(renovateConfigWithAutodiscovery),
		Committer: &github.CommitAuthor{
			Name:  github.Ptr("Renovate Lab"),
			Email: github.Ptr("lab@renovate.local"),
		},
	}

	_, _, err = client.Repositories.CreateFile(ctx, createdRepo.Owner.GetLogin(), createdRepo.GetName(),
		"renovate.json", renovateFileOpts)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create renovate.json")
		return fmt.Errorf("failed to create renovate.json: %w", err)
	}
	log.Debug().Msg("renovate.json created")

	// Add GitHub Actions workflow
	log.Debug().Msg("Adding GitHub Actions workflow")
	workflowFileOpts := &github.RepositoryContentFileOptions{
		Message: github.Ptr("ci: Add Renovate workflow for autodiscovery testing"),
		Content: []byte(renovateWorkflowYml),
		Committer: &github.CommitAuthor{
			Name:  github.Ptr("Renovate Lab"),
			Email: github.Ptr("lab@renovate.local"),
		},
	}

	_, _, err = client.Repositories.CreateFile(ctx, createdRepo.Owner.GetLogin(), createdRepo.GetName(),
		".github/workflows/renovate.yml", workflowFileOpts)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create workflow file")
		return fmt.Errorf("failed to create workflow file: %w", err)
	}
	log.Debug().Msg("GitHub Actions workflow created")

	log.Info().Msg("✓ Renovate Lab setup completed successfully!")
	log.Info().Msg("")
	log.Info().Str("url", createdRepo.GetHTMLURL()).Msg("Repository URL")
	log.Info().Str("clone", createdRepo.GetCloneURL()).Msg("Clone URL")
	log.Info().Msg("")
	log.Info().Msg("Next Steps:")
	log.Info().Msg("1. Configure your Renovate Bot to autodiscover in your account/organization")
	log.Info().Msg("2. Create a repository in your account/org and use 'pipeleek gh renovate autodiscovery' to set up the exploit")
	log.Info().Msg("3. The bot will automatically pick up the renovate.json configuration")
	log.Info().Msg("4. Check the GitHub Actions workflow for exploit execution proof")
	log.Info().Msg("")
	log.Info().Str("command", fmt.Sprintf("pipeleek gh renovate autodiscovery -t <token> -o <org/user> --repo-name %s --generate", createdRepo.Owner.GetLogin())).Msg("To populate repository with exploit files, run")

	return nil
}
