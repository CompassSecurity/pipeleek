package scan

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/gitlab/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func validOptions() Options {
	return Options{
		URL: "https://gitlab.example.com", Token: "test-token",
		Threads: 2, MaxBytes: 1024, HitTimeout: time.Second,
	}
}

func TestOptionsValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Options)
	}{
		{"url", func(o *Options) { o.URL = "file:///tmp" }},
		{"token", func(o *Options) { o.Token = "" }},
		{"threads", func(o *Options) { o.Threads = 0 }},
		{"size", func(o *Options) { o.MaxBytes = 0 }},
		{"timeout", func(o *Options) { o.HitTimeout = -1 }},
		{"limit", func(o *Options) { o.ReleaseLimit = -1 }},
		{"tag-requires-repo", func(o *Options) { o.Tag = "v1" }},
		{"tag-limit", func(o *Options) { o.Repo, o.Tag, o.ReleaseLimit = "g/p", "v1", 1 }},
		{"repo-namespace", func(o *Options) { o.Repo, o.Namespace = "g/p", "g" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := validOptions()
			tc.change(&o)
			require.Error(t, o.Validate())
		})
	}
	require.NoError(t, validOptions().Validate())
}

func TestReleasePaginationAndLimit(t *testing.T) {
	for _, limit := range []int{0, 1, 2} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			var releasePages atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/api/v4/projects/1/releases":
					releasePages.Add(1)
					assert.Equal(t, "released_at", r.URL.Query().Get("order_by"))
					assert.Equal(t, "desc", r.URL.Query().Get("sort"))
					if r.URL.Query().Get("page") == "2" {
						_, _ = fmt.Fprint(w, `[{"tag_name":"v1","assets":{"links":[{"name":"binary","url":"https://assets.example.com/binary"}]}}]`)
					} else {
						w.Header().Set("X-Next-Page", "2")
						_, _ = fmt.Fprint(w, `[{"tag_name":"future","upcoming_release":true},{"tag_name":"v2","assets":{"links":[{"name":"binary","url":"https://assets.example.com/binary"}]}}]`)
					}
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()
			git, err := util.GetGitlabClient("token", srv.URL)
			require.NoError(t, err)
			o := validOptions()
			o.ReleaseLimit = limit
			s := NewScanner(o)
			var assets []asset
			require.NoError(t, s.projectReleases(git, &gitlab.Project{
				ID: 1, PathWithNamespace: "g/p", WebURL: "https://gitlab.example.com/g/p",
			}, func(item asset) {
				assets = append(assets, item)
			}))
			expected := int64(2)
			if limit == 1 {
				expected = 1
			}
			assert.Equal(t, expected, s.releases.Load())
			assert.Equal(t, expected, releasePages.Load())
			assert.Len(t, assets, int(expected))
			for _, item := range assets {
				assert.Equal(t, "https://gitlab.example.com/g/p", item.project)
				assert.Equal(t, "https://assets.example.com/binary", item.rawURL)
			}
		})
	}
}

func TestExactTagAndSources(t *testing.T) {
	for _, sources := range []bool{false, true} {
		t.Run(fmt.Sprint(sources), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/api/v4/projects/1/releases/version/1":
					assert.Contains(t, r.URL.EscapedPath(), "version%2F1")
					_ = json.NewEncoder(w).Encode(gitlab.Release{
						TagName: "version/1", Name: "Release 1",
						Assets: gitlab.ReleaseAssets{
							Links: []*gitlab.ReleaseLink{
								{Name: "binary", URL: "/binary", DirectAssetURL: "https://gitlab.example.com/downloads/binary"},
							},
							Sources: []gitlab.ReleaseAssetsSource{
								{Format: "tar.gz", URL: "/source.tar.gz"}, {Format: "zip", URL: "/source.zip"},
							},
						},
					})
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()
			git, err := util.GetGitlabClient("token", srv.URL)
			require.NoError(t, err)
			o := validOptions()
			o.Repo, o.Tag, o.IncludeSources = "g/p", "version/1", sources
			s := NewScanner(o)
			var assets []asset
			require.NoError(t, s.projectReleases(git, &gitlab.Project{ID: 1}, func(item asset) {
				assets = append(assets, item)
			}))
			require.NotEmpty(t, assets)
			assert.Equal(t, "binary", assets[0].name)
			assert.Equal(t, "/binary", assets[0].rawURL)
			assert.Equal(t, "https://gitlab.example.com/downloads/binary", assets[0].webURL)
			if sources {
				require.Len(t, assets, 2)
				assert.Equal(t, "/source.zip", assets[1].rawURL)
				assert.Equal(t, "version/1.zip", assets[1].name)
				assert.Empty(t, assets[1].webURL)
			} else {
				assert.Len(t, assets, 1)
			}
			assert.Zero(t, s.failures.Load())
		})
	}
}

func TestDiscoveryContinuesAfterFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v4/projects":
			_, _ = fmt.Fprint(w, `[{"id":1,"path_with_namespace":"g/one"},{"id":2,"path_with_namespace":"g/two"}]`)
		case "/api/v4/projects/1/releases":
			w.WriteHeader(http.StatusNotFound)
		case "/api/v4/projects/2/releases":
			_, _ = fmt.Fprint(w, `[{"tag_name":"v1"}]`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	git, err := util.GetGitlabClient("token", srv.URL)
	require.NoError(t, err)
	o := validOptions()
	s := NewScanner(o)
	base, err := url.Parse(srv.URL)
	require.NoError(t, err)
	require.ErrorContains(t, s.scan(git, base), "incomplete")
	assert.Equal(t, int64(2), s.projects.Load())
	assert.Equal(t, int64(1), s.releases.Load())
	assert.Equal(t, int64(1), s.failures.Load())
}

func TestPublished(t *testing.T) {
	future, past := time.Now().Add(time.Hour), time.Now().Add(-time.Hour)
	assert.True(t, published(&gitlab.Release{}))
	assert.True(t, published(&gitlab.Release{ReleasedAt: &past}))
	assert.False(t, published(&gitlab.Release{ReleasedAt: &future}))
	assert.False(t, published(&gitlab.Release{UpcomingRelease: true}))
}

func TestForbiddenReleaseListingIsIgnored(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	git, err := util.GetGitlabClient("token", srv.URL)
	require.NoError(t, err)
	s := NewScanner(validOptions())
	require.NoError(t, s.projectReleases(git, &gitlab.Project{ID: 1}, func(asset) {
		t.Error("forbidden releases must not produce assets")
	}))
	assert.Zero(t, s.failures.Load())
	assert.Zero(t, s.releases.Load())
}

func TestProjectPagination(t *testing.T) {
	for _, namespace := range []string{"", "group"} {
		t.Run(namespace, func(t *testing.T) {
			var calls atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/api/v4/groups/group" {
					_, _ = fmt.Fprint(w, `{"id":10}`)
					return
				}
				calls.Add(1)
				if namespace == "" {
					assert.Equal(t, "/api/v4/projects", r.URL.Path)
					assert.Equal(t, "true", r.URL.Query().Get("membership"))
				} else {
					assert.Equal(t, "/api/v4/groups/10/projects", r.URL.Path)
					assert.Equal(t, "true", r.URL.Query().Get("include_subgroups"))
				}
				assert.Equal(t, "true", r.URL.Query().Get("owned"))
				assert.Equal(t, "test", r.URL.Query().Get("search"))
				if r.URL.Query().Get("page") != "2" {
					w.Header().Set("X-Next-Page", "2")
				}
				_, _ = fmt.Fprint(w, `[{"id":1}]`)
			}))
			defer srv.Close()
			git, err := util.GetGitlabClient("token", srv.URL)
			require.NoError(t, err)
			o := validOptions()
			o.Namespace, o.Owned, o.Member, o.Search = namespace, true, true, "test"
			s := NewScanner(o)
			var projects int
			require.NoError(t, s.projectsForScan(git, func(p *gitlab.Project) error {
				projects++
				return nil
			}))
			assert.Equal(t, 2, projects)
			assert.Equal(t, int64(2), calls.Load())
		})
	}
}

func TestMissingSources(t *testing.T) {
	o := validOptions()
	o.IncludeSources = true
	s := NewScanner(o)
	s.releaseAssets(&gitlab.Project{ID: 1}, &gitlab.Release{TagName: "v1"}, func(asset) {
		t.Error("release without assets must not produce work")
	})
	assert.Equal(t, int64(1), s.failures.Load())
	assert.Equal(t, int64(1), s.releases.Load())
}
