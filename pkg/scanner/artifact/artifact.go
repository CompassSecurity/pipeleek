package artifact

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/CompassSecurity/pipeleek/pkg/archive"
	"github.com/CompassSecurity/pipeleek/pkg/format"
	"github.com/CompassSecurity/pipeleek/pkg/logging"
	"github.com/CompassSecurity/pipeleek/pkg/scanner/engine"
	"github.com/CompassSecurity/pipeleek/pkg/scanner/types"
	"github.com/h2non/filetype"
	"github.com/rs/zerolog/log"
	"golift.io/xtractr"
)

var skippableDirectoryNames = []string{"node_modules", ".yarn", ".yarn-cache", ".npm", "venv", "vendor", ".go/pkg/mod/"}

type ScanOptions struct {
	VerifyCredentials bool
	HitTimeout        time.Duration
	GitLabURL         string
	ReportFinding     func(types.Finding, string, string)
}

func IsArchive(content []byte) bool {
	kind, _ := filetype.Match(content)
	return slices.Contains(xtractr.SupportedExtensions(), "."+kind.Extension)
}

func ScanFile(content []byte, filename string, opts ScanOptions) error {
	if opts.ReportFinding == nil {
		return errors.New("artifact finding reporter is required")
	}
	return scanFile(content, filename, "", opts, 1)
}

func scanFile(content []byte, filename, ancestry string, opts ScanOptions, depth int) error {
	if IsArchive(content) {
		return scanArchive(filename, content, ancestry, opts, depth)
	}
	return detectFile(content, filename, ancestry, opts)
}

func detectFile(content []byte, filename, ancestry string, opts ScanOptions) error {
	if !utf8.Valid(content) || bytes.ContainsRune(content, '\x00') {
		log.Debug().Str("file", filename).Msg("Binary artifact, extracting strings")
		content = archive.ExtractPrintableStrings(content, archive.MinStringLength)
	}
	findings, err := engine.DetectHitsWithOptions(content, 1, opts.VerifyCredentials,
		engine.DetectionOptions{Path: filename, GitLabURL: opts.GitLabURL, Timeout: opts.HitTimeout})
	if err != nil {
		return err
	}
	for _, finding := range findings {
		opts.ReportFinding(finding, filename, ancestry)
	}
	return nil
}

func DetectFileHits(content []byte, jobWebUrl string, jobName string, fileName string, archiveName string, enableSecretsVerification bool, hitTimeout time.Duration) {
	opts := ScanOptions{
		VerifyCredentials: enableSecretsVerification, HitTimeout: hitTimeout,
		ReportFinding: func(finding types.Finding, file, ancestry string) {
			ReportFinding(finding, jobWebUrl, jobName, file, ancestry)
		},
	}
	if err := detectFile(content, fileName, archiveName, opts); err != nil {
		log.Debug().Err(err).Str("job", jobWebUrl).Msg("Failed detecting secrets")
	}
}

func HandleArchiveArtifact(archivefileName string, content []byte, jobWebUrl string, jobName string, enableSecretsVerification bool, hitTimeout time.Duration) {
	HandleArchiveArtifactWithDepth(archivefileName, content, jobWebUrl, jobName, enableSecretsVerification, hitTimeout, 1)
}

func HandleArchiveArtifactWithDepth(archivefileName string, content []byte, jobWebUrl string, jobName string, enableSecretsVerification bool, hitTimeout time.Duration, depth int) {
	opts := ScanOptions{
		VerifyCredentials: enableSecretsVerification, HitTimeout: hitTimeout,
		ReportFinding: func(finding types.Finding, file, ancestry string) {
			ReportFinding(finding, jobWebUrl, jobName, file, ancestry)
		},
	}
	if err := scanFile(content, archivefileName, "", opts, depth); err != nil {
		log.Error().Err(err).Str("file", archivefileName).Msg("Failed scanning artifact")
	}
}

func scanArchive(archivefileName string, content []byte, ancestry string, opts ScanOptions, depth int) error {
	if depth > 10 {
		return errors.New("maximum archive nesting depth exceeded")
	}

	for _, skipKeyword := range skippableDirectoryNames {
		if strings.Contains(archivefileName, skipKeyword) {
			log.Debug().Str("file", archivefileName).Str("keyword", skipKeyword).Msg("Skipped archive due to blocklist entry")
			return nil
		}
	}

	fileType, err := filetype.Get(content)
	if err != nil {
		return fmt.Errorf("determine archive type: %w", err)
	}

	tmpArchiveFile, err := os.CreateTemp("", "pipeleek-artifact-archive-*."+fileType.Extension)
	if err != nil {
		return fmt.Errorf("create archive file: %w", err)
	}
	defer func() { _ = tmpArchiveFile.Close() }()

	_, err = tmpArchiveFile.Write(content)
	if err != nil {
		return fmt.Errorf("write archive file: %w", err)
	}
	defer func() { _ = os.Remove(tmpArchiveFile.Name()) }()

	tmpArchiveFilesDirectory, err := os.MkdirTemp("", "pipeleek-artifact-archive-out-")
	if err != nil {
		return fmt.Errorf("create archive directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpArchiveFilesDirectory) }()

	x := &xtractr.XFile{
		FilePath:  tmpArchiveFile.Name(),
		OutputDir: tmpArchiveFilesDirectory,
		FileMode:  0o600,
		DirMode:   0o700,
	}

	_, files, _, err := xtractr.ExtractFile(x)
	if err != nil {
		return fmt.Errorf("extract archive %q: %w", archivefileName, err)
	}

	if ancestry != "" {
		ancestry += " -> "
	}
	ancestry += archivefileName
	var failures []error
	for _, fPath := range files {
		// TAR returns member names; other extractors return absolute paths.
		if !filepath.IsAbs(fPath) {
			fPath = filepath.Join(tmpArchiveFilesDirectory, fPath)
		}
		if !format.IsDirectory(fPath) {
			// #nosec G304 - Reading extracted artifact files from temp directory, path controlled by xtractr library
			fileBytes, err := os.ReadFile(fPath)
			if err != nil {
				failures = append(failures, fmt.Errorf("read archive member: %w", err))
				continue
			}

			currentFileName, err := filepath.Rel(tmpArchiveFilesDirectory, fPath)
			if err != nil {
				failures = append(failures, err)
				continue
			}
			if err := scanFile(fileBytes, filepath.ToSlash(currentFileName), ancestry, opts, depth+1); err != nil {
				failures = append(failures, err)
			}
		}
	}
	return errors.Join(failures...)
}

func ReportFinding(finding types.Finding, url string, jobName string, fileName string, archiveName string) {
	secretType := logging.SecretTypeArchive
	if len(archiveName) > 0 {
		secretType = logging.SecretTypeNestedArchive
	}

	event := logging.Hit().
		Str("type", string(secretType)).
		Str("confidence", finding.Pattern.Pattern.Confidence).
		Str("ruleName", finding.Pattern.Pattern.Name).
		Str("value", finding.Text).
		Engine(finding.Engine).
		Str("url", url).
		Str("jobName", jobName).
		Str("file", fileName)

	if len(archiveName) > 0 {
		event = event.Str("archive", archiveName)
	}

	event.Msg("SECRET")
}
