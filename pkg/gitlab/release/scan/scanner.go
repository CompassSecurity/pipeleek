package scan

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync/atomic"
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/config"
	"github.com/CompassSecurity/pipeleek/pkg/gitlab/util"
	"github.com/CompassSecurity/pipeleek/pkg/logging"
	"github.com/CompassSecurity/pipeleek/pkg/scan/result"
	"github.com/CompassSecurity/pipeleek/pkg/scan/runner"
	"github.com/CompassSecurity/pipeleek/pkg/scanner"
	scannerartifact "github.com/CompassSecurity/pipeleek/pkg/scanner/artifact"
	"github.com/CompassSecurity/pipeleek/pkg/scanner/engine"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/wandb/parallel"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

type Options struct {
	URL                 string
	Token               string
	Repo                string
	Namespace           string
	Search              string
	Owned               bool
	Member              bool
	Tag                 string
	ReleaseLimit        int
	IncludeSources      bool
	MaxBytes            int64
	Threads             int
	SecretsVerification bool
	Confidence          []string
	HitTimeout          time.Duration
}

func (o Options) Validate() error {
	if err := config.ValidateURL(o.URL, "GitLab URL"); err != nil {
		return err
	}
	if err := config.ValidateToken(o.Token, "GitLab API Token"); err != nil {
		return err
	}
	if err := config.ValidateThreadCount(o.Threads); err != nil {
		return err
	}
	switch {
	case o.Repo != "" && o.Namespace != "":
		return errors.New("--repo and --namespace are mutually exclusive")
	case o.Tag != "" && o.Repo == "":
		return errors.New("--tag requires --repo")
	case o.Tag != "" && o.ReleaseLimit != 0:
		return errors.New("--tag and a nonzero --release-limit are mutually exclusive")
	case o.ReleaseLimit < 0:
		return errors.New("--release-limit must be nonnegative")
	case o.MaxBytes <= 0 || o.MaxBytes == math.MaxInt64:
		return errors.New("--max-artifact-size must be positive and smaller than 8 EiB")
	case o.HitTimeout <= 0:
		return errors.New("--hit-timeout must be positive")
	}
	return nil
}

type Scanner struct {
	options  Options
	projects atomic.Int64
	releases atomic.Int64
	scanned  atomic.Int64
	skipped  atomic.Int64
	failures atomic.Int64
}

var _ scanner.BaseScanner = (*Scanner)(nil)

func NewScanner(opts Options) *Scanner {
	return &Scanner{options: opts}
}

func (s *Scanner) Status() *zerolog.Event {
	return log.Info().
		Int64("projects", s.projects.Load()).
		Int64("releases", s.releases.Load()).
		Int64("scannedAssets", s.scanned.Load()).
		Int64("skippedAssets", s.skipped.Load()).
		Int64("failures", s.failures.Load())
}

type asset struct {
	project string
	tag     string
	release string
	name    string
	rawURL  string
	webURL  string
}

func (s *Scanner) Scan() error {
	if err := s.options.Validate(); err != nil {
		return err
	}
	git, err := util.GetGitlabClient(s.options.Token, s.options.URL)
	if err != nil {
		return fmt.Errorf("creating GitLab client: %w", err)
	}
	runner.InitScanner(s.options.Confidence)
	base, err := url.Parse(s.options.URL)
	if err != nil {
		return errors.New("invalid GitLab URL")
	}
	return s.scan(git, base)
}

func (s *Scanner) scan(git *gitlab.Client, base *url.URL) error {
	workers := parallel.Limited(context.Background(), s.options.Threads)
	enqueue := func(item asset) {
		workers.Go(func(context.Context) {
			s.scanAsset(base, item)
		})
	}
	err := s.projectsForScan(git, func(project *gitlab.Project) error {
		s.projects.Add(1)
		if project.WebURL == "" {
			project.WebURL = base.JoinPath(project.PathWithNamespace).String()
		}
		log.Debug().Str("project", project.WebURL).Msg("Fetch project releases")
		if err := s.projectReleases(git, project, enqueue); err != nil {
			s.failures.Add(1)
			log.Error().Err(err).Str("project", project.WebURL).Msg("Failed discovering release assets")
		}
		return nil
	})
	workers.Wait()
	if err != nil {
		s.failures.Add(1)
		log.Error().Err(err).Msg("Failed discovering projects")
	}
	s.Status().Msg("Release scan finished")
	if n := s.failures.Load(); n > 0 {
		return fmt.Errorf("release scan incomplete: %d failure(s)", n)
	}
	return nil
}

func (s *Scanner) projectsForScan(git *gitlab.Client, visit util.ProjectIteratorFunc) error {
	o := s.options
	if o.Repo != "" {
		project, _, err := git.Projects.GetProject(o.Repo, &gitlab.GetProjectOptions{})
		if err != nil {
			return fmt.Errorf("fetching repository: %w", err)
		}
		return visit(project)
	}
	if o.Namespace != "" {
		group, _, err := git.Groups.GetGroup(o.Namespace, &gitlab.GetGroupOptions{})
		if err != nil {
			return fmt.Errorf("fetching namespace: %w", err)
		}
		return util.IterateGroupProjects(git, group.ID, &gitlab.ListGroupProjectsOptions{
			ListOptions: gitlab.ListOptions{PerPage: 100, Page: 1},
			OrderBy:     gitlab.Ptr("last_activity_at"), Owned: gitlab.Ptr(o.Owned),
			Search: gitlab.Ptr(o.Search), WithShared: gitlab.Ptr(true), IncludeSubGroups: gitlab.Ptr(true),
		}, visit)
	}
	return util.IterateProjects(git, &gitlab.ListProjectsOptions{
		ListOptions: gitlab.ListOptions{PerPage: 100, Page: 1},
		Owned:       gitlab.Ptr(o.Owned), Membership: gitlab.Ptr(o.Member),
		Search: gitlab.Ptr(o.Search), OrderBy: gitlab.Ptr("last_activity_at"),
	}, visit)
}

func (s *Scanner) projectReleases(git *gitlab.Client, project *gitlab.Project, visit func(asset)) error {
	if s.options.Tag != "" {
		release, _, err := git.Releases.GetRelease(project.ID, s.options.Tag)
		if err != nil {
			return fmt.Errorf("fetching release: %w", err)
		}
		if published(release) {
			s.releaseAssets(project, release, visit)
		}
		return nil
	}
	opts := &gitlab.ListReleasesOptions{
		ListOptions: gitlab.ListOptions{PerPage: 100, Page: 1},
		OrderBy:     gitlab.Ptr("released_at"), Sort: gitlab.Ptr("desc"),
	}
	count := 0
	for {
		releases, resp, err := git.Releases.ListReleases(project.ID, opts)
		if err != nil {
			if resp != nil && resp.StatusCode == http.StatusForbidden {
				return nil
			}
			return fmt.Errorf("listing releases: %w", err)
		}
		for _, release := range releases {
			if !published(release) {
				continue
			}
			s.releaseAssets(project, release, visit)
			count++
			if s.options.ReleaseLimit > 0 && count >= s.options.ReleaseLimit {
				return nil
			}
		}
		if resp == nil || resp.NextPage == 0 {
			return nil
		}
		opts.Page = resp.NextPage
	}
}

func published(release *gitlab.Release) bool {
	return !release.UpcomingRelease && (release.ReleasedAt == nil || !release.ReleasedAt.After(time.Now()))
}

func (s *Scanner) releaseAssets(project *gitlab.Project, release *gitlab.Release, visit func(asset)) {
	s.releases.Add(1)
	item := asset{project: project.WebURL, tag: release.TagName, release: release.Name}
	for _, link := range release.Assets.Links {
		item.name, item.rawURL, item.webURL = link.Name, link.URL, link.DirectAssetURL
		visit(item)
	}
	if !s.options.IncludeSources {
		return
	}
	for _, source := range release.Assets.Sources {
		if source.Format == "zip" {
			item.name, item.rawURL, item.webURL = release.TagName+".zip", source.URL, ""
			visit(item)
			return
		}
	}
	s.failures.Add(1)
	log.Error().Str("project", item.project).Str("tag", item.tag).Msg("Source ZIP unavailable for release")
}

func (s *Scanner) scanAsset(base *url.URL, item asset) {
	u, err := base.Parse(item.rawURL)
	if err != nil {
		s.assetFailure(item, errors.New("invalid asset URL"))
		return
	}
	filename := path.Base(u.Path)
	if filename == "." || filename == "/" {
		filename = item.name
	}
	if item.name == "" {
		item.name = filename
	}
	if item.webURL == "" {
		item.webURL = strings.TrimRight(item.project, "/") + "/-/releases/" + url.PathEscape(item.tag)
	}
	content, err := downloadAsset(u.String(), base, s.options.Token, s.options.MaxBytes)
	if err == nil {
		err = scannerartifact.ScanFile(content, filename, scannerartifact.ScanOptions{
			VerifyCredentials: s.options.SecretsVerification,
			HitTimeout:        s.options.HitTimeout, GitLabURL: s.options.URL,
			ReportFinding: func(finding scanner.Finding, file, archive string) {
				sourceType := logging.SecretTypeArchive
				if archive != "" {
					sourceType = logging.SecretTypeNestedArchive
				}
				result.ReportFindingWithCustomFields(finding, map[string]string{
					"type":    string(sourceType),
					"url":     item.webURL,
					"project": item.project,
					"tag":     item.tag, "release": item.release, "asset": item.name,
					"file": file, "archive": archive,
				})
			},
		})
	}
	if errors.Is(err, errAssetUnavailable) {
		s.skipped.Add(1)
	} else if errors.Is(err, errAssetTooLarge) {
		s.skipped.Add(1)
		log.Debug().Str("project", item.project).Str("tag", item.tag).Str("asset", item.name).
			Msg("Skipped release asset exceeding maximum size")
	} else if err != nil {
		s.assetFailure(item, err)
	} else {
		s.scanned.Add(1)
	}
}

func (s *Scanner) assetFailure(item asset, err error) {
	s.failures.Add(1)
	event := log.Error()
	if errors.Is(err, engine.ErrHitTimeout) {
		event = log.Warn()
	}
	event.Err(err).Str("project", item.project).Str("tag", item.tag).
		Str("asset", item.name).Msg("Failed scanning release asset")
}
