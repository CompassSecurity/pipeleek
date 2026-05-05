package scan

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/format"
	"github.com/CompassSecurity/pipeleek/pkg/httpclient"
	"github.com/CompassSecurity/pipeleek/pkg/logging"
	artifactproc "github.com/CompassSecurity/pipeleek/pkg/scan/artifact"
	"github.com/CompassSecurity/pipeleek/pkg/scan/logline"
	"github.com/CompassSecurity/pipeleek/pkg/scan/result"
	"github.com/h2non/filetype"
	"github.com/nsqio/go-diskqueue"
	"github.com/rs/zerolog/log"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

type QueueItemType string

const (
	QueueItemJobTrace QueueItemType = "jobTrace"
	QueueItemArtifact QueueItemType = "artifact"
	QueueItemDotenv   QueueItemType = "dotenv"
)

type QueueMeta struct {
	ProjectId                int
	JobId                    int
	JobWebUrl                string
	JobName                  string
	ProjectPathWithNamespace string
	ArtifactSize             int64
}

type QueueItem struct {
	Type        QueueItemType `json:"type"`
	ScanOptions *ScanOptions  `json:"scanOptions"`
	Meta        QueueMeta     `json:"meta"`
}

func setupQueue(options *ScanOptions) (diskqueue.Interface, string) {
	log.Debug().Msg("Setting up queue on disk")

	queueDirectory := options.QueueFolder
	if queueDirectory == "" {
		queueDirectory = os.TempDir()
	} else if !filepath.IsAbs(queueDirectory) {
		cwd, err := os.Getwd()
		if err != nil {
			log.Fatal().Err(err).Msg("Could not determine current working directory")
		}
		queueDirectory = filepath.Join(cwd, queueDirectory)
	}

	if err := os.MkdirAll(queueDirectory, 0700); err != nil {
		log.Fatal().Err(err).Msg("Failed to create queue directory")
	}

	tmpfile, err := os.CreateTemp(queueDirectory, "pipeleek-queue-db-")
	if err != nil {
		log.Fatal().Err(err).Msg("Creating temp DB file failed")
	}

	queueFile := tmpfile.Name()
	_ = tmpfile.Close()

	q := diskqueue.New(
		filepath.Base(queueFile),
		queueDirectory,
		512,           // max segment size
		0,             // min segment size
		math.MaxInt32, // max messages
		2500,          // max buffer size
		2*time.Second, // flush interval
		func(lvl diskqueue.LogLevel, f string, args ...interface{}) {
			// disable diskqueue logging
		},
	)

	log.Debug().Str("queueFile", queueFile).Msg("Queue setup complete")
	return q, queueFile
}

func analyzeQueueItem(serializeditem []byte, git *gitlab.Client, options *ScanOptions, wg *sync.WaitGroup) {
	defer wg.Done()

	var item QueueItem
	err := json.Unmarshal(serializeditem, &item)
	if err != nil {
		log.Error().Err(err).Msg("Failed unmarshalling queue item")
	}

	if item.Type == QueueItemJobTrace {
		analyzeJobTrace(git, item, options)
	}

	if item.Type == QueueItemArtifact {
		analyzeJobArtifact(git, item, options)
		runtime.GC()
	}

	if item.Type == QueueItemDotenv {
		analyzeDotenvArtifact(git, item, options)
	}
}

func enqueueItem(queue diskqueue.Interface, qType QueueItemType, meta QueueMeta, wg *sync.WaitGroup) {
	item := &QueueItem{Type: qType, Meta: meta}
	itemBytes, err := json.Marshal(item)
	if err != nil {
		log.Error().Str("type", string(qType)).Err(err).Msg("Failed marshalling job item")
		return
	}
	err = queue.Put(itemBytes)
	if err != nil {
		log.Error().Str("type", string(qType)).Err(err).Msg("Failed put'ing the queue item")
		return
	}

	wg.Add(1)
}

func analyzeJobTrace(git *gitlab.Client, item QueueItem, options *ScanOptions) {
	trace := getJobTrace(git, item.Meta.ProjectId, item.Meta.JobId, item.Meta.JobWebUrl, options)
	if len(trace) < 1 {
		return
	}

	logResult, err := logline.ProcessLogs(trace, logline.ProcessOptions{
		MaxGoRoutines:     options.MaxScanGoRoutines,
		VerifyCredentials: options.TruffleHogVerification,
		BuildURL:          item.Meta.JobWebUrl,
		JobName:           item.Meta.JobName,
		HitTimeout:        options.HitTimeout,
	})
	if err != nil {
		log.Debug().Err(err).Int("project", item.Meta.ProjectId).Int("job", item.Meta.JobId).Msg("Failed detecting secrets")
		return
	}

	result.ReportFindings(logResult.Findings, result.ReportOptions{
		LocationURL: item.Meta.JobWebUrl,
		JobName:     item.Meta.JobName,
	})
}

func analyzeJobArtifact(git *gitlab.Client, item QueueItem, options *ScanOptions) {
	// Check artifact size before downloading
	if item.Meta.ArtifactSize > 0 && item.Meta.ArtifactSize > options.MaxArtifactSize {
		log.Debug().
			Int64("bytes", item.Meta.ArtifactSize).
			Int64("maxBytes", options.MaxArtifactSize).
			Str("name", item.Meta.JobName).
			Str("url", item.Meta.JobWebUrl).
			Msg("Skipped large artifact")
		return
	}

	data := getJobArtifacts(git, item.Meta.ProjectId, item.Meta.JobId, item.Meta.JobWebUrl, options)
	if data == nil {
		return
	}

	_, err := artifactproc.ProcessZipArtifact(data, artifactproc.ProcessOptions{
		MaxGoRoutines:     options.MaxScanGoRoutines,
		VerifyCredentials: options.TruffleHogVerification,
		BuildURL:          item.Meta.JobWebUrl,
		ArtifactName:      item.Meta.JobName,
		HitTimeout:        options.HitTimeout,
	})
	if err != nil {
		log.Debug().Err(err).Int("project", item.Meta.ProjectId).Int("job", item.Meta.JobId).Msg("Unable to process artifacts")
		return
	}
}

func analyzeDotenvArtifact(git *gitlab.Client, item QueueItem, options *ScanOptions) {
	dotenvText := getDotenvArtifact(git, item.Meta.ProjectId, item.Meta.JobId, item.Meta.ProjectPathWithNamespace, options)
	if dotenvText == nil {
		return
	}

	logResult, err := logline.ProcessLogs(dotenvText, logline.ProcessOptions{
		MaxGoRoutines:     options.MaxScanGoRoutines,
		VerifyCredentials: options.TruffleHogVerification,
		BuildURL:          item.Meta.JobWebUrl,
		HitTimeout:        options.HitTimeout,
	})
	if err != nil {
		log.Debug().Err(err).Int("project", item.Meta.ProjectId).Int("job", item.Meta.JobId).Msg("Failed detecting secrets")
		return
	}

	for _, finding := range logResult.Findings {
		result.ReportFindingWithCustomFields(finding, map[string]string{
			"type": string(logging.SecretTypeDotenv),
			"url":  item.Meta.JobWebUrl,
			"note": "Check artifacts page - dotenv files are only downloadable there",
		})
	}
}

func getJobTrace(git *gitlab.Client, projectId int, jobId int, jobWebUrl string, options *ScanOptions) []byte {
	if isUnauthenticatedMode(options) {
		return getJobTraceViaWeb(jobWebUrl, options)
	}

	reader, resp, err := git.Jobs.GetTraceFile(projectId, int64(jobId))

	if resp != nil && (resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 404) {
		log.Debug().Int("project", projectId).Int("job", jobId).Int("status", resp.StatusCode).Msg("Job trace is not publicly accessible")
		return nil
	}

	if err != nil {
		log.Error().Stack().Err(err).Msg("Failed fetching job trace")
		return nil
	}
	trace, err := io.ReadAll(reader)
	if err != nil {
		log.Error().Stack().Err(err).Msg("Failed reading trace reader into byte array")
		return nil
	}

	return trace
}

// getJobTraceViaWeb fetches a job trace using the public web raw URL (/-/jobs/:id/raw).
// This works for public projects even without an API token.
func getJobTraceViaWeb(jobWebUrl string, options *ScanOptions) []byte {
	rawURL, err := url.JoinPath(jobWebUrl, "raw")
	if err != nil {
		log.Debug().Err(err).Str("url", jobWebUrl).Msg("Failed building raw job trace URL")
		return nil
	}

	client := httpclient.GetPipeleekHTTPClient(options.GitlabUrl, nil, nil).StandardClient()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		log.Debug().Err(err).Str("url", rawURL).Msg("Failed building request for web trace")
		return nil
	}

	if options.GitlabCookie != "" {
		req.Header.Set("Cookie", "_gitlab_session="+options.GitlabCookie)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Debug().Err(err).Str("url", rawURL).Msg("Failed fetching job trace via web URL")
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Debug().Str("url", rawURL).Int("status", resp.StatusCode).Msg("Job trace not accessible via web URL")
		return nil
	}

	trace, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Debug().Err(err).Str("url", rawURL).Msg("Failed reading web trace response")
		return nil
	}

	return trace
}

func getJobArtifacts(git *gitlab.Client, projectId int, jobId int, jobWebUrl string, options *ScanOptions) []byte {
	artifactsReader, resp, err := git.Jobs.GetJobArtifacts(projectId, int64(jobId))

	if resp != nil {
		if resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 404 {
			if resp.StatusCode != 404 {
				log.Debug().Int("project", projectId).Int("job", jobId).Int("status", resp.StatusCode).Str("url", jobWebUrl).Msg("Job artifacts are not publicly accessible")
			}
			return nil
		}
	}

	if err != nil {
		log.Error().Err(err).Str("url", jobWebUrl).Msg("Failed downloading job artifacts zip")
		return nil
	}

	if artifactsReader.Size() > options.MaxArtifactSize {
		log.Debug().Int64("bytes", artifactsReader.Size()).Int64("maxBytes", options.MaxArtifactSize).Str("url", jobWebUrl).Msg("Skipped large artifact Zip")
		return nil
	}

	data, err := io.ReadAll(artifactsReader)
	if err != nil {
		log.Error().Err(err).Str("url", jobWebUrl).Msg("Failed reading artifacts stream")
		return nil
	}

	extractedZipSize := format.CalculateZipFileSize(data)
	// Safe conversion: MaxArtifactSize is always positive in valid configs
	if options.MaxArtifactSize < 0 || extractedZipSize > uint64(options.MaxArtifactSize) {
		log.Debug().Str("url", jobWebUrl).Int64("zipBytes", artifactsReader.Size()).Uint64("bytesExtracted", extractedZipSize).Int64("maxBytes", options.MaxArtifactSize).Msg("Skipped large extracted Zip artifact")
		return nil
	}

	if len(data) > 1 {
		return data
	}

	return nil
}

// dotenv artifacts are not listed in the API thus a request must always be made
func getDotenvArtifact(git *gitlab.Client, projectId int, jobId int, projectPathWithNamespace string, options *ScanOptions) []byte {
	if len(options.GitlabCookie) > 1 {
		envTxt := DownloadEnvArtifact(options.GitlabCookie, options.GitlabUrl, projectPathWithNamespace, jobId)
		if len(envTxt) > 1 {
			return envTxt
		}
	}

	return nil
}

// .env artifacts are not accessible over the API thus we must use session cookie and use the UI path
func DownloadEnvArtifact(cookieVal string, gitlabUrl string, prjectPath string, jobId int) []byte {
	dotenvUrl, err := url.JoinPath(gitlabUrl, prjectPath, "/-/jobs/", strconv.Itoa(jobId), "/artifacts/download")
	if err != nil {
		log.Debug().Stack().Err(err).Msg("Failed joining dotenv GET request URL")
		return []byte{}
	}

	reqUrl, err := url.Parse(dotenvUrl)
	if err != nil {
		log.Debug().Stack().Err(err).Msg("Failed parsing dotenv URL")
		return []byte{}
	}
	q := reqUrl.Query()
	q.Add("file_type", "dotenv")
	reqUrl.RawQuery = q.Encode()
	dotenvUrl = reqUrl.String()

	// #nosec G124 - Cookie attributes (Secure/HttpOnly/SameSite) are server-side browser directives; not applicable for client HTTP requests
	client := httpclient.GetPipeleekHTTPClient(gitlabUrl, []*http.Cookie{{Name: "_gitlab_session", Value: cookieVal}}, nil)
	resp, err := client.Get(dotenvUrl)
	if err != nil {
		log.Debug().Stack().Err(err).Msg("Failed requesting dotenv artifact")
		return []byte{}
	}
	defer func() { _ = resp.Body.Close() }()

	statCode := resp.StatusCode

	// means no dotenv exists
	if statCode == 404 {
		return []byte{}
	}

	if statCode != 200 {
		log.Error().Stack().Err(err).Int("HTTP", statCode).Msg("Invalid _gitlab_session detected")
		return []byte{}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Debug().Err(err).Msg("Failed reading dotenv response body")
		return []byte{}
	}

	kind, err := filetype.Match(body)
	if err != nil {
		log.Debug().Err(err).Msg("Unable to match the filetype of the dotenv response body")
		return []byte{}
	}

	if kind.Extension == "gz" {
		reader := bytes.NewReader(body)
		gzreader, err := gzip.NewReader(reader)
		if err != nil {
			log.Debug().Err(err).Msg("Failed gunzipping dotenv response body")
			return []byte{}
		}

		envText, err := io.ReadAll(gzreader)
		if err != nil {
			log.Debug().Stack().Err(err).Msg("failed uncompressing dotenv archive")
			return []byte{}
		}

		return envText
	} else if filetype.Unknown == kind {
		htmlPageTitle := format.ExtractHTMLTitleFromB64Html(body)
		log.Error().Str("filetype", kind.Extension).Str("url", dotenvUrl).Int("httpStatus", statCode).Str("htmlPageTitle", htmlPageTitle).Msg("Dotenv artifact file is unexpected. Check if the cookie and token have the same access!")
	} else {
		log.Error().Str("filetype", kind.Extension).Str("url", dotenvUrl).Int("httpStatus", statCode).Any("body", body).Msg("Dotenv file response is a weird file type, unexpected behavior, open a bug report if you see this")
	}

	return []byte{}
}
