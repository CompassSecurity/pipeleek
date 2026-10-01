package gitea

import (
	"fmt"

	"code.gitea.io/sdk/gitea"
	"github.com/CompassSecurity/pipeleek/pkg/logging"
	artifactproc "github.com/CompassSecurity/pipeleek/pkg/scan/artifact"
	"github.com/CompassSecurity/pipeleek/pkg/scan/logline"
	"github.com/CompassSecurity/pipeleek/pkg/scan/result"
	"github.com/CompassSecurity/pipeleek/pkg/scanner"
	"github.com/h2non/filetype"
	"github.com/rs/zerolog/log"
)

func scanLogs(logBytes []byte, repo *gitea.Repository, run ActionWorkflowRun, jobID int64, jobName string) {
	if repo == nil {
		log.Error().Msg("Cannot scan logs: repository is nil")
		return
	}

	logResult, err := logline.ProcessLogs(logBytes, logline.ProcessOptions{
		MaxGoRoutines:     scanOptions.MaxScanGoRoutines,
		VerifyCredentials: scanOptions.SecretsVerification,
		HitTimeout:        scanOptions.HitTimeout,
	})
	if err != nil {
		log.Debug().Err(err).
			Str("repo", repo.FullName).
			Int64("run_id", run.ID).
			Int64("job_id", jobID).
			Msg("Failed detecting secrets in logs")
		return
	}

	// Report findings with custom fields for Gitea-specific metadata
	for _, finding := range logResult.Findings {
		logFinding(finding, repo.FullName, run.ID, jobID, jobName, run.HTMLURL)
	}
}

func logFinding(finding scanner.Finding, repoFullName string, runID, jobID int64, jobName, url string) {
	customFields := map[string]string{
		"type":   string(logging.SecretTypeLog),
		"repo":   repoFullName,
		"run_id": fmt.Sprintf("%d", runID),
		"url":    url,
	}

	if jobID > 0 {
		customFields["job_id"] = fmt.Sprintf("%d", jobID)
	}

	if jobName != "" {
		customFields["job_name"] = jobName
	}

	result.ReportFindingWithCustomFields(finding, customFields)
}

func processZipArtifact(zipBytes []byte, repo *gitea.Repository, run ActionWorkflowRun, artifactName string) {
	if repo == nil {
		log.Error().Msg("Cannot process artifact: repository is nil")
		return
	}

	_, err := artifactproc.ProcessZipArtifact(zipBytes, artifactproc.ProcessOptions{
		MaxGoRoutines:     scanOptions.MaxScanGoRoutines,
		VerifyCredentials: scanOptions.SecretsVerification,
		BuildURL:          run.HTMLURL,
		ArtifactName:      artifactName,
		WorkflowRunName:   run.Name,
		HitTimeout:        scanOptions.HitTimeout,
	})

	if err != nil {
		log.Debug().
			Str("repo", repo.FullName).
			Int64("run_id", run.ID).
			Str("artifact", artifactName).
			Msg("Artifact is not a zip, scanning directly")
		scanArtifactContent(zipBytes, repo, run, artifactName, "")
		return
	}
}

func determineFileAction(content []byte, displayName string) (action string, fileType string) {
	kind, _ := filetype.Match(content)

	if filetype.IsArchive(content) {
		return "archive", kind.MIME.Value
	}

	if kind != filetype.Unknown {
		return "skip", kind.MIME.Value
	}

	return "scan", kind.MIME.Value
}

func scanArtifactContent(content []byte, repo *gitea.Repository, run ActionWorkflowRun, artifactName string, fileName string) {
	displayName := artifactName
	if fileName != "" {
		displayName = fmt.Sprintf("%s/%s", artifactName, fileName)
	}

	action, fileType := determineFileAction(content, displayName)

	switch action {
	case "archive":
		scanner.HandleArchiveArtifact(displayName, content, run.HTMLURL, run.Name, scanOptions.SecretsVerification, scanOptions.HitTimeout)
	case "skip":
		log.Trace().
			Str("file", displayName).
			Str("type", fileType).
			Msg("Unknown file type, scanning as text")
		scanner.DetectFileHits(content, run.HTMLURL, run.Name, displayName, repo.FullName, scanOptions.SecretsVerification, scanOptions.HitTimeout)
	case "scan":
		log.Debug().
			Str("file", displayName).
			Str("type", fileType).
			Msg("Not an archive file type, scanning as text")
		scanner.DetectFileHits(content, run.HTMLURL, run.Name, displayName, repo.FullName, scanOptions.SecretsVerification, scanOptions.HitTimeout)
	}
}
