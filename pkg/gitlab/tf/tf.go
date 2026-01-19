package tf

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/httpclient"
	"github.com/CompassSecurity/pipeleek/pkg/gitlab/util"
	"github.com/CompassSecurity/pipeleek/pkg/logging"
	"github.com/CompassSecurity/pipeleek/pkg/scanner"
	"github.com/rs/zerolog/log"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

type TFOptions struct {
	GitlabUrl              string
	GitlabApiToken         string
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

// ScanTerraformStates scans all Terraform/OpenTofu state files for secrets
func ScanTerraformStates(options TFOptions) {
	log.Info().Msg("Starting Terraform state scan")

	// Initialize scanner
	scanner.InitRules(options.ConfidenceFilter)
	if !options.TruffleHogVerification {
		log.Info().Msg("TruffleHog verification is disabled")
	}

	// Create output directory
	if err := os.MkdirAll(options.OutputDir, 0o755); err != nil {
		log.Fatal().Err(err).Str("dir", options.OutputDir).Msg("Failed to create output directory")
	}

	// Initialize GitLab client
	git, err := util.GetGitlabClient(options.GitlabApiToken, options.GitlabUrl)
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Failed creating gitlab client")
	}

	// Fetch all projects with maintainer access
	states := fetchTerraformStates(git, options.GitlabUrl, options.GitlabApiToken)
	log.Info().Int("total", len(states)).Msg("Found Terraform states")

	if len(states) == 0 {
		log.Warn().Msg("No Terraform states found")
		return
	}

	// Download and scan states with concurrency
	downloadAndScanStates(states, options)

	log.Info().Msg("Terraform state scan complete")
}

// fetchTerraformStates iterates all projects and finds those with Terraform state
func fetchTerraformStates(git *gitlab.Client, gitlabUrl string, token string) []terraformState {
	var states []terraformState
	var mu sync.Mutex

	projectOpts := &gitlab.ListProjectsOptions{
		ListOptions: gitlab.ListOptions{PerPage: 100, Page: 1},
		MinAccessLevel: gitlab.Ptr(gitlab.MaintainerPermissions),
		OrderBy:        gitlab.Ptr("last_activity_at"),
	}

	log.Info().Msg("Fetching projects with maintainer access")

	err := util.IterateProjects(git, projectOpts, func(project *gitlab.Project) error {
		log.Debug().Str("project", project.PathWithNamespace).Int64("id", project.ID).Msg("Checking project for Terraform state")

		// Check for Terraform state using HTTP API
		stateExists := checkTerraformState(gitlabUrl, token, int(project.ID))
		if stateExists {
			mu.Lock()
			states = append(states, terraformState{
				Name:      "default",
				ProjectID: int(project.ID),
				Project:   project,
			})
			mu.Unlock()

			log.Info().Str("project", project.PathWithNamespace).Msg("Found Terraform state")
		}
		return nil
	})

	if err != nil {
		log.Error().Err(err).Msg("Error iterating projects")
	}

	return states
}

// checkTerraformState checks if a project has a Terraform state
func checkTerraformState(gitlabUrl string, token string, projectID int) bool {
	url := fmt.Sprintf("%s/api/v4/projects/%d/terraform/state/default", gitlabUrl, projectID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("PRIVATE-TOKEN", token)

	client := httpclient.GetPipeleekHTTPClient("", nil, nil).StandardClient()
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// 200 means state exists, 404 means no state
	return resp.StatusCode == http.StatusOK
}

// downloadAndScanStates downloads state files and scans them for secrets
func downloadAndScanStates(states []terraformState, options TFOptions) {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, options.Threads)

	for _, state := range states {
		wg.Add(1)
		go func(s terraformState) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			downloadAndScan(s, options)
		}(state)
	}

	wg.Wait()
}

// downloadAndScan downloads a single state file and scans it
func downloadAndScan(state terraformState, options TFOptions) {
	// Download state file
	url := fmt.Sprintf("%s/api/v4/projects/%d/terraform/state/%s", options.GitlabUrl, state.ProjectID, state.Name)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Error().Err(err).Str("project", state.Project.PathWithNamespace).Str("state", state.Name).Msg("Failed to create request")
		return
	}
	req.Header.Set("PRIVATE-TOKEN", options.GitlabApiToken)

	client := httpclient.GetPipeleekHTTPClient("", nil, nil).StandardClient()
	resp, err := client.Do(req)
	if err != nil {
		log.Error().Err(err).Str("project", state.Project.PathWithNamespace).Str("state", state.Name).Msg("Failed to download Terraform state")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Error().Int("status", resp.StatusCode).Str("project", state.Project.PathWithNamespace).Str("state", state.Name).Msg("Failed to download Terraform state")
		return
	}

	// Read state data
	stateData, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error().Err(err).Str("project", state.Project.PathWithNamespace).Str("state", state.Name).Msg("Failed to read state data")
		return
	}

	// Save to file
	filename := fmt.Sprintf("%d_%s.tfstate", state.ProjectID, sanitizeFilename(state.Name))
	filePath := filepath.Join(options.OutputDir, filename)

	if err := os.WriteFile(filePath, stateData, 0o644); err != nil {
		log.Error().Err(err).Str("file", filePath).Msg("Failed to write state file")
		return
	}

	log.Info().Str("project", state.Project.PathWithNamespace).Str("state", state.Name).Str("file", filePath).Msg("Downloaded Terraform state")

	// Scan the file for secrets
	scanStateFile(stateData, filePath, state, options)
}

// scanStateFile scans a Terraform state file for secrets
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

// sanitizeFilename removes invalid characters from filenames
func sanitizeFilename(name string) string {
	// Replace common invalid characters
	replacements := map[rune]rune{
		'/':  '_',
		'\\': '_',
		':':  '_',
		'*':  '_',
		'?':  '_',
		'"':  '_',
		'<':  '_',
		'>':  '_',
		'|':  '_',
	}

	runes := []rune(name)
	for i, r := range runes {
		if replacement, ok := replacements[r]; ok {
			runes[i] = replacement
		}
	}

	return string(runes)
}
