package tf

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/gitlab/util"
	"github.com/CompassSecurity/pipeleek/pkg/logging"
	"github.com/CompassSecurity/pipeleek/pkg/scanner"
	"github.com/rs/zerolog/log"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

type TFOptions struct {
	GitlabUrl              string
	GitlabApiToken         string
	GitlabClient           *gitlab.Client
	OutputDir              string
	Threads                int
	ConfidenceFilter       []string
	TruffleHogVerification bool
	HitTimeout             time.Duration
}

type terraformState struct {
	Name      string
	ProjectID int
	Project   *gitlab.Project
}

func ScanTerraformStates(options TFOptions) {
	log.Info().Msg("Starting Terraform state scan")

	scanner.InitRules(options.ConfidenceFilter)
	if !options.TruffleHogVerification {
		log.Info().Msg("TruffleHog verification is disabled")
	}

	if err := os.MkdirAll(options.OutputDir, 0o750); err != nil {
		log.Fatal().Err(err).Str("dir", options.OutputDir).Msg("Failed to create output directory")
	}

	git, err := util.GetGitlabClient(options.GitlabApiToken, options.GitlabUrl)
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Failed creating gitlab client")
	}
	options.GitlabClient = git

	states := fetchTerraformStates(git)
	log.Info().Int("total", len(states)).Msg("Found Terraform states")

	if len(states) == 0 {
		log.Warn().Msg("No Terraform states found")
		return
	}

	for _, state := range states {
		stateData, filePath, ok := downloadStateFile(state, options)
		if !ok {
			continue
		}

		scanStateFile(stateData, filePath, state, options)
	}

	log.Info().Msg("Terraform state scan complete")
}

func fetchTerraformStates(git *gitlab.Client) []terraformState {
	var states []terraformState

	projectOpts := &gitlab.ListProjectsOptions{
		ListOptions:    gitlab.ListOptions{PerPage: 100, Page: 1},
		MinAccessLevel: gitlab.Ptr(gitlab.MaintainerPermissions),
		OrderBy:        gitlab.Ptr("last_activity_at"),
	}

	log.Info().Msg("Fetching projects with maintainer access")

	err := util.IterateProjects(git, projectOpts, func(project *gitlab.Project) error {
		log.Debug().Str("project", project.PathWithNamespace).Int64("id", project.ID).Msg("Checking project for Terraform state")

		stateList, _, err := git.TerraformStates.List(project.PathWithNamespace)
		if err != nil {
			if errors.Is(err, gitlab.ErrNotFound) {
				return nil
			}
			log.Error().Err(err).Str("project", project.PathWithNamespace).Msg("Failed to list Terraform states")
			return nil
		}

		if len(stateList) == 0 {
			return nil
		}

		for _, state := range stateList {
			if state.Name == "" {
				continue
			}
			states = append(states, terraformState{
				Name:      state.Name,
				ProjectID: int(project.ID),
				Project:   project,
			})
		}

		log.Info().Str("project", project.PathWithNamespace).Int("states", len(stateList)).Msg("Found Terraform states")
		return nil
	})

	if err != nil {
		log.Error().Err(err).Msg("Error iterating projects")
	}

	return states
}

func downloadStateFile(state terraformState, options TFOptions) ([]byte, string, bool) {
	reader, _, err := options.GitlabClient.TerraformStates.DownloadLatest(state.ProjectID, state.Name)
	if err != nil {
		log.Error().Err(err).Str("project", state.Project.PathWithNamespace).Str("state", state.Name).Msg("Failed to download Terraform state")
		return nil, "", false
	}

	stateData, err := io.ReadAll(reader)
	if err != nil {
		log.Error().Err(err).Str("project", state.Project.PathWithNamespace).Str("state", state.Name).Msg("Failed to read state data")
		return nil, "", false
	}

	filename := fmt.Sprintf("%d_%s.tfstate", state.ProjectID, url.PathEscape(state.Name))
	filePath := filepath.Join(options.OutputDir, filename)

	if err := os.WriteFile(filePath, stateData, 0o600); err != nil {
		log.Error().Err(err).Str("file", filePath).Msg("Failed to write state file")
		return nil, "", false
	}

	log.Info().Str("project", state.Project.PathWithNamespace).Str("state", state.Name).Str("file", filePath).Msg("Downloaded Terraform state")

	return stateData, filePath, true
}

func scanStateFile(content []byte, filePath string, state terraformState, options TFOptions) {
	log.Debug().Str("file", filePath).Msg("Scanning Terraform state for secrets")

	findings, err := scanner.DetectHits(content, options.Threads, options.TruffleHogVerification, options.HitTimeout)
	if err != nil {
		log.Debug().Err(err).Str("file", filePath).Msg("Failed detecting secrets")
		return
	}

	if len(findings) > 0 {
		log.Warn().Int("findings", len(findings)).Str("project", state.Project.PathWithNamespace).Str("state", state.Name).Str("file", filePath).Msg("Secrets found in Terraform state")

		for _, finding := range findings {
			logging.Hit().
				Str("type", "terraform-state").
				Str("project", state.Project.PathWithNamespace).
				Str("url", state.Project.WebURL).
				Str("state", state.Name).
				Str("file", filePath).
				Str("ruleName", finding.Pattern.Pattern.Name).
				Str("confidence", finding.Pattern.Pattern.Confidence).
				Str("value", finding.Text).
				Msg("SECRET")
		}
	}
}
