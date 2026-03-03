package runners

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func TestMergeRunnerMaps(t *testing.T) {
	tests := []struct {
		name           string
		projectRunners map[int64]RunnerResult
		groupRunners   map[int64]RunnerResult
		expectedCount  int
		description    string
	}{
		{
			name: "no overlap",
			projectRunners: map[int64]RunnerResult{
				1: {Runner: &gitlab.Runner{ID: 1}, Project: &gitlab.Project{Name: "project1"}},
				2: {Runner: &gitlab.Runner{ID: 2}, Project: &gitlab.Project{Name: "project2"}},
			},
			groupRunners: map[int64]RunnerResult{
				3: {Runner: &gitlab.Runner{ID: 3}, Group: &gitlab.Group{Name: "group1"}},
				4: {Runner: &gitlab.Runner{ID: 4}, Group: &gitlab.Group{Name: "group2"}},
			},
			expectedCount: 4,
			description:   "Should merge all runners when no IDs overlap",
		},
		{
			name: "complete overlap - project takes precedence",
			projectRunners: map[int64]RunnerResult{
				1: {Runner: &gitlab.Runner{ID: 1}, Project: &gitlab.Project{Name: "project1"}},
			},
			groupRunners: map[int64]RunnerResult{
				1: {Runner: &gitlab.Runner{ID: 1}, Group: &gitlab.Group{Name: "group1"}},
			},
			expectedCount: 1,
			description:   "Should deduplicate when same runner in project and group",
		},
		{
			name: "partial overlap",
			projectRunners: map[int64]RunnerResult{
				1: {Runner: &gitlab.Runner{ID: 1}, Project: &gitlab.Project{Name: "project1"}},
				2: {Runner: &gitlab.Runner{ID: 2}, Project: &gitlab.Project{Name: "project2"}},
			},
			groupRunners: map[int64]RunnerResult{
				2: {Runner: &gitlab.Runner{ID: 2}, Group: &gitlab.Group{Name: "group1"}},
				3: {Runner: &gitlab.Runner{ID: 3}, Group: &gitlab.Group{Name: "group2"}},
			},
			expectedCount: 3,
			description:   "Should merge with partial overlap, keeping project version",
		},
		{
			name:           "empty project runners",
			projectRunners: map[int64]RunnerResult{},
			groupRunners: map[int64]RunnerResult{
				1: {Runner: &gitlab.Runner{ID: 1}, Group: &gitlab.Group{Name: "group1"}},
			},
			expectedCount: 1,
			description:   "Should handle empty project runners",
		},
		{
			name: "empty group runners",
			projectRunners: map[int64]RunnerResult{
				1: {Runner: &gitlab.Runner{ID: 1}, Project: &gitlab.Project{Name: "project1"}},
			},
			groupRunners:  map[int64]RunnerResult{},
			expectedCount: 1,
			description:   "Should handle empty group runners",
		},
		{
			name:           "both empty",
			projectRunners: map[int64]RunnerResult{},
			groupRunners:   map[int64]RunnerResult{},
			expectedCount:  0,
			description:    "Should handle both empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			merged := MergeRunnerMaps(tt.projectRunners, tt.groupRunners)
			assert.Len(t, merged, tt.expectedCount, tt.description)

			// Verify project runners take precedence
			if tt.name == "complete overlap - project takes precedence" {
				result, exists := merged[1]
				require.True(t, exists)
				assert.NotNil(t, result.Project, "Should keep project reference")
				assert.Equal(t, "project1", result.Project.Name)
			}
		})
	}
}

func TestFormatRunnerInfo(t *testing.T) {
	tests := []struct {
		name        string
		result      RunnerResult
		details     *gitlab.RunnerDetails
		expectNil   bool
		sourceType  string
		sourceName  string
		description string
	}{
		{
			name: "project runner",
			result: RunnerResult{
				Runner:  &gitlab.Runner{ID: 1},
				Project: &gitlab.Project{Name: "my-project", ID: 123},
			},
			details: &gitlab.RunnerDetails{
				ID:          1,
				Name:        "runner-1",
				Description: "Test runner",
				RunnerType:  "project_type",
				Paused:      false,
				TagList:     []string{"docker", "linux"},
			},
			sourceType:  "project",
			sourceName:  "my-project",
			description: "Should format project runner info correctly",
		},
		{
			name: "group runner",
			result: RunnerResult{
				Runner: &gitlab.Runner{ID: 2},
				Group:  &gitlab.Group{Name: "my-group", ID: 456},
			},
			details: &gitlab.RunnerDetails{
				ID:          2,
				Name:        "runner-2",
				Description: "Group runner",
				RunnerType:  "group_type",
				Paused:      true,
				TagList:     []string{"kubernetes"},
			},
			sourceType:  "group",
			sourceName:  "my-group",
			description: "Should format group runner info correctly",
		},
		{
			name: "nil details",
			result: RunnerResult{
				Runner:  &gitlab.Runner{ID: 3},
				Project: &gitlab.Project{Name: "test"},
			},
			details:     nil,
			expectNil:   true,
			description: "Should handle nil details",
		},
		{
			name: "runner with no tags",
			result: RunnerResult{
				Runner:  &gitlab.Runner{ID: 4},
				Project: &gitlab.Project{Name: "test-project"},
			},
			details: &gitlab.RunnerDetails{
				ID:          4,
				Name:        "no-tags-runner",
				Description: "Runner without tags",
				RunnerType:  "instance_type",
				Paused:      false,
				TagList:     []string{},
			},
			sourceType:  "project",
			sourceName:  "test-project",
			description: "Should handle runners with no tags",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := FormatRunnerInfo(tt.result, tt.details)

			if tt.expectNil {
				assert.Nil(t, info)
				return
			}

			require.NotNil(t, info)
			assert.Equal(t, int(tt.details.ID), info.ID)
			assert.Equal(t, tt.details.Name, info.Name)
			assert.Equal(t, tt.details.Description, info.Description)
			assert.Equal(t, tt.details.RunnerType, info.Type)
			assert.Equal(t, tt.details.Paused, info.Paused)
			assert.Equal(t, tt.details.TagList, info.Tags)
			assert.Equal(t, tt.sourceType, info.SourceType)
			assert.Equal(t, tt.sourceName, info.SourceName)
		})
	}
}

func TestExtractUniqueTags(t *testing.T) {
	tests := []struct {
		name         string
		runners      []*gitlab.RunnerDetails
		expectedTags int
		description  string
	}{
		{
			name: "multiple runners with unique tags",
			runners: []*gitlab.RunnerDetails{
				{TagList: []string{"docker", "linux"}},
				{TagList: []string{"kubernetes", "cloud"}},
			},
			expectedTags: 4,
			description:  "Should collect all unique tags",
		},
		{
			name: "runners with duplicate tags",
			runners: []*gitlab.RunnerDetails{
				{TagList: []string{"docker", "linux"}},
				{TagList: []string{"docker", "windows"}},
				{TagList: []string{"linux", "mac"}},
			},
			expectedTags: 4, // docker, linux, windows, mac
			description:  "Should deduplicate tags across runners",
		},
		{
			name: "empty tag lists",
			runners: []*gitlab.RunnerDetails{
				{TagList: []string{}},
				{TagList: []string{}},
			},
			expectedTags: 0,
			description:  "Should handle empty tag lists",
		},
		{
			name:         "no runners",
			runners:      []*gitlab.RunnerDetails{},
			expectedTags: 0,
			description:  "Should handle no runners",
		},
		{
			name: "single runner with multiple tags",
			runners: []*gitlab.RunnerDetails{
				{TagList: []string{"tag1", "tag2", "tag3"}},
			},
			expectedTags: 3,
			description:  "Should extract all tags from single runner",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tags := ExtractUniqueTags(tt.runners)
			assert.Len(t, tags, tt.expectedTags, tt.description)

			// Verify uniqueness
			tagSet := make(map[string]bool)
			for _, tag := range tags {
				assert.False(t, tagSet[tag], "Tags should be unique")
				tagSet[tag] = true
			}
		})
	}
}

func TestFormatTagsString(t *testing.T) {
	tests := []struct {
		name     string
		tags     []string
		expected string
	}{
		{
			name:     "multiple tags",
			tags:     []string{"docker", "linux", "kubernetes"},
			expected: "docker,linux,kubernetes",
		},
		{
			name:     "single tag",
			tags:     []string{"docker"},
			expected: "docker",
		},
		{
			name:     "empty tags",
			tags:     []string{},
			expected: "",
		},
		{
			name:     "tags with spaces",
			tags:     []string{"my tag", "another tag"},
			expected: "my tag,another tag",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatTagsString(tt.tags)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCountRunnersBySource(t *testing.T) {
	tests := []struct {
		name          string
		runnerMap     map[int64]RunnerResult
		expectedProj  int
		expectedGroup int
		description   string
	}{
		{
			name: "mixed sources",
			runnerMap: map[int64]RunnerResult{
				1: {Runner: &gitlab.Runner{ID: 1}, Project: &gitlab.Project{Name: "p1"}},
				2: {Runner: &gitlab.Runner{ID: 2}, Project: &gitlab.Project{Name: "p2"}},
				3: {Runner: &gitlab.Runner{ID: 3}, Group: &gitlab.Group{Name: "g1"}},
			},
			expectedProj:  2,
			expectedGroup: 1,
			description:   "Should count both project and group runners",
		},
		{
			name: "only project runners",
			runnerMap: map[int64]RunnerResult{
				1: {Runner: &gitlab.Runner{ID: 1}, Project: &gitlab.Project{Name: "p1"}},
				2: {Runner: &gitlab.Runner{ID: 2}, Project: &gitlab.Project{Name: "p2"}},
			},
			expectedProj:  2,
			expectedGroup: 0,
			description:   "Should handle only project runners",
		},
		{
			name: "only group runners",
			runnerMap: map[int64]RunnerResult{
				1: {Runner: &gitlab.Runner{ID: 1}, Group: &gitlab.Group{Name: "g1"}},
				2: {Runner: &gitlab.Runner{ID: 2}, Group: &gitlab.Group{Name: "g2"}},
			},
			expectedProj:  0,
			expectedGroup: 2,
			description:   "Should handle only group runners",
		},
		{
			name:          "empty map",
			runnerMap:     map[int64]RunnerResult{},
			expectedProj:  0,
			expectedGroup: 0,
			description:   "Should handle empty map",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			projCount, groupCount := CountRunnersBySource(tt.runnerMap)
			assert.Equal(t, tt.expectedProj, projCount, "Project count: "+tt.description)
			assert.Equal(t, tt.expectedGroup, groupCount, "Group count: "+tt.description)
		})
	}
}

func TestListProjectRunners(t *testing.T) {
	// Mock server for projects and runners
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case strings.Contains(r.URL.Path, "/api/v4/projects") && !strings.Contains(r.URL.Path, "/runners"):
			// Return a single project page
			projects := []*gitlab.Project{{ID: 1, Name: "test-project", PathWithNamespace: "org/test-project"}}
			_ = json.NewEncoder(w).Encode(projects)

		case strings.Contains(r.URL.Path, "/projects/") && strings.Contains(r.URL.Path, "/runners"):
			// Return runners for project
			runners := []*gitlab.Runner{{ID: 100, Name: "runner-1"}, {ID: 101, Name: "runner-2"}}
			_ = json.NewEncoder(w).Encode(runners)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client, err := gitlab.NewClient("token", gitlab.WithBaseURL(srv.URL))
	require.NoError(t, err)

	result := listProjectRunners(client)
	assert.Len(t, result, 2, "Should return 2 runners")

	_, ok := result[100]
	assert.True(t, ok, "Runner 100 should be in the result")
	_, ok = result[101]
	assert.True(t, ok, "Runner 101 should be in the result")
}

func TestListProjectRunners_Empty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/api/v4/projects") {
			// Return empty project list
			_ = json.NewEncoder(w).Encode([]*gitlab.Project{})
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client, err := gitlab.NewClient("token", gitlab.WithBaseURL(srv.URL))
	require.NoError(t, err)

	result := listProjectRunners(client)
	assert.Empty(t, result, "Should return empty map for no projects")
}

func TestListGroupRunners(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/api/v4/groups":
			groups := []*gitlab.Group{{ID: 10, Name: "test-group"}}
			_ = json.NewEncoder(w).Encode(groups)

		case strings.Contains(r.URL.Path, "/api/v4/groups/") && strings.Contains(r.URL.Path, "/runners"):
			runners := []*gitlab.Runner{{ID: 200, Name: "group-runner-1"}}
			_ = json.NewEncoder(w).Encode(runners)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client, err := gitlab.NewClient("token", gitlab.WithBaseURL(srv.URL))
	require.NoError(t, err)

	result := listGroupRunners(client)
	assert.Len(t, result, 1, "Should return 1 group runner")
	_, ok := result[200]
	assert.True(t, ok, "Runner 200 should be in the result")
}

func TestListGroupRunners_Empty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v4/groups" {
			_ = json.NewEncoder(w).Encode([]*gitlab.Group{})
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client, err := gitlab.NewClient("token", gitlab.WithBaseURL(srv.URL))
	require.NoError(t, err)

	result := listGroupRunners(client)
	assert.Empty(t, result, "Should return empty map for no groups")
}
