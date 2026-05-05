package scan

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/gitlab/util"
	"github.com/CompassSecurity/pipeleek/pkg/scan/runner"
	"github.com/CompassSecurity/pipeleek/pkg/system"
	"github.com/nsqio/go-diskqueue"
	"github.com/rs/zerolog/log"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

var globQueue diskqueue.Interface
var waitGroup *sync.WaitGroup
var queueFileName string

type ScanOptions struct {
	GitlabUrl              string
	GitlabApiToken         string
	GitlabCookie           string
	ProjectSearchQuery     string
	Artifacts              bool
	Owned                  bool
	Member                 bool
	Repository             string
	Namespace              string
	JobLimit               int
	ConfidenceFilter       []string
	MaxArtifactSize        int64
	MaxScanGoRoutines      int
	QueueFolder            string
	TruffleHogVerification bool
	HitTimeout             time.Duration
}

func ScanGitLabPipelines(options *ScanOptions) {
	globQueue, queueFileName = setupQueue(options)
	system.RegisterGracefulShutdownHandler(cleanUp)

	if isUnauthenticatedMode(options) {
		log.Info().Msg("Running in unauthenticated mode: only publicly accessible resources will be scanned")
	}

	runner.InitScanner(options.ConfidenceFilter)
	if !options.TruffleHogVerification {
		log.Info().Msg("TruffleHog verification is disabled")
	}

	git, err := util.GetGitlabClient(options.GitlabApiToken, options.GitlabUrl)
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Failed creating gitlab client")
	}

	// waitgroup is used to coordinate termination
	// dont kill the queue before the jobs have been fetched
	waitGroup = new(sync.WaitGroup)
	waitGroup.Add(1)

	if len(options.GitlabCookie) > 0 {
		util.CookieSessionValid(options.GitlabUrl, options.GitlabCookie)
	}

	if len(options.ProjectSearchQuery) > 0 && options.Repository == "" {
		log.Info().Str("query", options.ProjectSearchQuery).Msg("Filtering scanned projects by")
	}

	if options.Repository != "" {
		go scanRepository(git, options, waitGroup)
	} else if options.Namespace != "" {
		go scanNamespace(git, options, waitGroup)
	} else {
		go fetchProjects(git, options, waitGroup)
	}

	go func() {
		queueChan := globQueue.ReadChan()
		for qitem := range queueChan {
			analyzeQueueItem(qitem, git, options, waitGroup)
		}
	}()

	waitGroup.Wait()
	cleanUp()
}

func scanRepository(git *gitlab.Client, options *ScanOptions, wg *sync.WaitGroup) {
	defer wg.Done()

	log.Info().Str("repository", options.Repository).Msg("Scanning repository pipelines")

	project, resp, err := git.Projects.GetProject(options.Repository, &gitlab.GetProjectOptions{})
	if err != nil {
		if isUnauthenticatedMode(options) {
			log.Warn().Err(err).Str("repository", options.Repository).Msg("Repository is not publicly accessible in unauthenticated mode")
			return
		}
		log.Fatal().Stack().Err(err).Str("repository", options.Repository).Msg("Failed fetching project by repository name")
	}

	if resp != nil && resp.StatusCode == 404 {
		if isUnauthenticatedMode(options) {
			log.Warn().Str("repository", options.Repository).Msg("Project not found or not publicly accessible")
			return
		}
		log.Fatal().Str("repository", options.Repository).Msg("Project not found")
	}

	getAllJobs(git, project, options)
	log.Info().Msg("Done scanning repository")
}

func scanNamespace(git *gitlab.Client, options *ScanOptions, wg *sync.WaitGroup) {
	defer wg.Done()

	log.Info().Str("namespace", options.Namespace).Msg("Scanning namespace pipelines")
	group, _, err := git.Groups.GetGroup(options.Namespace, &gitlab.GetGroupOptions{})

	if err != nil {
		if isUnauthenticatedMode(options) {
			log.Warn().Err(err).Str("namespace", options.Namespace).Msg("Namespace is not publicly accessible in unauthenticated mode")
			return
		}
		log.Fatal().Stack().Err(err).Msg("Failed fetching namespace")
	}

	projectOpts := &gitlab.ListGroupProjectsOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: 100,
			Page:    1,
		},
		OrderBy:          gitlab.Ptr("last_activity_at"),
		Owned:            gitlab.Ptr(options.Owned),
		Search:           gitlab.Ptr(options.ProjectSearchQuery),
		WithShared:       gitlab.Ptr(true),
		IncludeSubGroups: gitlab.Ptr(true),
	}

	err = util.IterateGroupProjects(git, group.ID, projectOpts, func(project *gitlab.Project) error {
		log.Debug().Str("url", project.WebURL).Msg("Fetch project jobs")
		getAllJobs(git, project, options)
		return nil
	})
	if err != nil {
		log.Error().Stack().Err(err).Msg("Failed iterating namespace projects")
		return
	}

	log.Info().Msg("Fetched all namespace projects")
}

func cleanUp() {
	log.Debug().Msg("Cleaning up")
	err := globQueue.Delete()
	if err != nil {
		log.Fatal().Err(err).Msg("Error deleteing queue on shutdown")
	}

	files, err := filepath.Glob(queueFileName + "*")
	if err != nil {
		log.Fatal().Err(err).Msg("Error removing database files")
	}
	for _, f := range files {
		err := os.Remove(f)
		if err != nil {
			log.Fatal().Err(err).Str("file", f).Msg("Error deleting database file")
		}
		log.Trace().Str("file", f).Msg("Deleted")
	}
	_ = os.Remove(queueFileName)
}

func fetchProjects(git *gitlab.Client, options *ScanOptions, wg *sync.WaitGroup) {
	defer wg.Done()

	log.Info().Msg("Fetching projects")

	projectOpts := &gitlab.ListProjectsOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: 100,
			Page:    1,
		},
		Owned:      gitlab.Ptr(options.Owned),
		Membership: gitlab.Ptr(options.Member),
		Search:     gitlab.Ptr(options.ProjectSearchQuery),
		OrderBy:    gitlab.Ptr("last_activity_at"),
	}

	err := util.IterateProjects(git, projectOpts, func(project *gitlab.Project) error {
		log.Debug().Str("url", project.WebURL).Msg("Fetch project jobs")
		getAllJobs(git, project, options)
		return nil
	})
	if err != nil {
		log.Error().Stack().Err(err).Msg("Failed iterating projects")
		return
	}

	log.Info().Msg("Fetched all projects")
}

func getAllJobs(git *gitlab.Client, project *gitlab.Project, options *ScanOptions) {

	if isUnauthenticatedMode(options) {
		getAllJobsViaPipelines(git, project, options)
		return
	}

	opts := &gitlab.ListJobsOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: 100,
			Page:    1,
		},
	}

	currentJobCtr := 0

jobOut:
	for {
		jobs, resp, err := git.Jobs.ListProjectJobs(project.ID, opts)

		if err != nil {
			log.Debug().Stack().Err(err).Msg("Failed fetching project jobs")
			break
		}

		if resp != nil && (resp.StatusCode == 401 || resp.StatusCode == 403) {
			break
		}

		for _, job := range jobs {
			currentJobCtr += 1
			log.Trace().Str("url", getJobUrl(git, project, job)).Msg("Enqueue job for scanning")

			// Get artifact size if available
			var artifactSize int64 = 0
			if job.ArtifactsFile.Size > 0 {
				artifactSize = int64(job.ArtifactsFile.Size)
			}

			meta := QueueMeta{
				JobId:                    int(job.ID),
				ProjectId:                int(project.ID),
				JobWebUrl:                getJobUrl(git, project, job),
				JobName:                  job.Name,
				ProjectPathWithNamespace: project.PathWithNamespace,
				ArtifactSize:             artifactSize,
			}
			enqueueItem(globQueue, QueueItemJobTrace, meta, waitGroup)

			if options.Artifacts {
				enqueueItem(globQueue, QueueItemArtifact, meta, waitGroup)
				if len(options.GitlabCookie) > 1 {
					enqueueItem(globQueue, QueueItemDotenv, meta, waitGroup)
				}
			}

			if options.JobLimit > 0 && currentJobCtr >= options.JobLimit {
				break jobOut
			}
		}

		if resp.NextPage == 0 {
			break
		}

		opts.Page = resp.NextPage
	}

}

func isUnauthenticatedMode(options *ScanOptions) bool {
	return strings.TrimSpace(options.GitlabApiToken) == ""
}

// getAllJobsViaPipelines enqueues jobs by iterating pipelines then their jobs.
// Used as a fallback for unauthenticated mode where the project-level jobs API is restricted.
func getAllJobsViaPipelines(git *gitlab.Client, project *gitlab.Project, options *ScanOptions) {
	pipelineOpts := &gitlab.ListProjectPipelinesOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: 100,
			Page:    1,
		},
	}

	currentJobCtr := 0

pipelineOut:
	for {
		pipelines, resp, err := git.Pipelines.ListProjectPipelines(project.ID, pipelineOpts)
		if err != nil || (resp != nil && (resp.StatusCode == 401 || resp.StatusCode == 403)) {
			log.Trace().Err(err).Str("project", project.PathWithNamespace).Msg("Pipelines not publicly accessible, skipping")
			break
		}

		for _, pipeline := range pipelines {
			jobOpts := &gitlab.ListJobsOptions{
				ListOptions: gitlab.ListOptions{
					PerPage: 100,
					Page:    1,
				},
			}
			for {
				jobs, jresp, jerr := git.Jobs.ListPipelineJobs(project.ID, pipeline.ID, jobOpts)
				if jerr != nil || (jresp != nil && (jresp.StatusCode == 401 || jresp.StatusCode == 403)) {
					break
				}

				for _, job := range jobs {
					currentJobCtr++
					log.Trace().Str("url", getJobUrl(git, project, job)).Msg("Enqueue job for scanning (via pipelines)")

					var artifactSize int64
					if job.ArtifactsFile.Size > 0 {
						artifactSize = int64(job.ArtifactsFile.Size)
					}

					meta := QueueMeta{
						JobId:                    int(job.ID),
						ProjectId:                int(project.ID),
						JobWebUrl:                getJobUrl(git, project, job),
						JobName:                  job.Name,
						ProjectPathWithNamespace: project.PathWithNamespace,
						ArtifactSize:             artifactSize,
					}
					enqueueItem(globQueue, QueueItemJobTrace, meta, waitGroup)

					if options.Artifacts {
						enqueueItem(globQueue, QueueItemArtifact, meta, waitGroup)
					}

					if options.JobLimit > 0 && currentJobCtr >= options.JobLimit {
						break pipelineOut
					}
				}

				if jresp == nil || jresp.NextPage == 0 {
					break
				}
				jobOpts.Page = jresp.NextPage
			}
		}

		if resp.NextPage == 0 {
			break
		}
		pipelineOpts.Page = resp.NextPage
	}
}

func getJobUrl(git *gitlab.Client, project *gitlab.Project, job *gitlab.Job) string {
	return git.BaseURL().Host + "/" + project.PathWithNamespace + "/-/jobs/" + strconv.FormatInt(job.ID, 10)
}

func GetQueueStatus() int {
	if globQueue == nil {
		return 0
	}
	return int(globQueue.Depth())
}
