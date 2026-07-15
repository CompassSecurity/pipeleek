package enum

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func TestWriteHTMLReport(t *testing.T) {
	tmpDir := t.TempDir()
	output := filepath.Join(tmpDir, "enum-report.html")

	result := &EnumResult{
		GeneratedAt:    time.Date(2026, 7, 6, 8, 0, 0, 0, time.UTC),
		GitLabURL:      "https://gitlab.example.com",
		MinAccessLevel: int(gitlab.GuestPermissions),
		User: &gitlab.User{
			Username: "testuser",
			Name:     "Test User",
			Email:    "test@example.com",
		},
		UsersEnumerated: true,
		Users: []*gitlab.User{
			{
				Username: "alice",
				Name:     "Alice Example",
				Email:    "alice@example.com",
				State:    "active",
				WebURL:   "https://gitlab.example.com/alice",
			},
		},
		Token: &SelfToken{Name: "demo-token", Scopes: []string{"api", "read_api"}},
		Associations: &TokenAssociations{
			Groups: []TokenAssociationGroup{{ID: 1, Name: "security-team", WebURL: "https://gitlab.example.com/groups/security-team", Visibility: "private", AccessLevels: 50}},
			Projects: []TokenAssociationProject{{
				ID:                2,
				NameWithNamespace: "security-team / security-tools",
				WebURL:            "https://gitlab.example.com/security-team/security-tools",
				Visibility:        "private",
				AccessLevels:      TokenAssociationProjectAccess{GroupAccessLevel: 50, ProjectAccessLevel: 0},
			}},
		},
	}

	err := WriteHTMLReport(result, output)
	require.NoError(t, err)

	content, err := os.ReadFile(output)
	require.NoError(t, err)
	assert.Contains(t, string(content), "GitLab Enumeration Report")
	assert.Contains(t, string(content), "security-team / security-tools")
	assert.Contains(t, string(content), "Minimum access level:")
	assert.Contains(t, string(content), "top-nav")
	assert.Contains(t, string(content), "top-nav-brand")
	assert.Contains(t, string(content), "<svg")
	assert.Contains(t, string(content), "users-section")
	assert.Contains(t, string(content), "users-filter-query")
	assert.Contains(t, string(content), "alice@example.com")
	assert.Contains(t, string(content), "groups-filter-access")
	assert.Contains(t, string(content), "groups-filter-username")
	assert.Contains(t, string(content), "projects-filter-effective")
	assert.Contains(t, string(content), "projects-filter-username")
	assert.Contains(t, string(content), "groups-visible-count")
	assert.Contains(t, string(content), "projects-visible-count")
	assert.Contains(t, string(content), "users-visible-count")
	assert.Contains(t, string(content), "toggle-full-width")
	assert.Contains(t, string(content), "back-to-top")
}

func TestWriteHTMLReport_MembersShowNAWhenUsersNotEnumerated(t *testing.T) {
	tmpDir := t.TempDir()
	output := filepath.Join(tmpDir, "enum-report-no-users.html")

	result := &EnumResult{
		GeneratedAt:     time.Date(2026, 7, 6, 8, 0, 0, 0, time.UTC),
		GitLabURL:       "https://gitlab.example.com",
		MinAccessLevel:  int(gitlab.GuestPermissions),
		UsersEnumerated: false,
		Associations: &TokenAssociations{
			Groups: []TokenAssociationGroup{{
				ID:           1,
				Name:         "security-team",
				WebURL:       "https://gitlab.example.com/groups/security-team",
				Visibility:   "private",
				AccessLevels: 30,
			}},
			Projects: []TokenAssociationProject{{
				ID:                2,
				NameWithNamespace: "security-team / security-tools",
				WebURL:            "https://gitlab.example.com/security-team/security-tools",
				Visibility:        "private",
				AccessLevels:      TokenAssociationProjectAccess{GroupAccessLevel: 30, ProjectAccessLevel: 0},
			}},
		},
	}

	err := WriteHTMLReport(result, output)
	require.NoError(t, err)

	content, err := os.ReadFile(output)
	require.NoError(t, err)

	// Groups + Projects members columns should display N/A when users enrichment is disabled.
	assert.Equal(t, 2, strings.Count(string(content), "N/A"))
}

func TestWriteHTMLReport_MembersShowNAWhenMembersInaccessible(t *testing.T) {
	tmpDir := t.TempDir()
	output := filepath.Join(tmpDir, "enum-report-members-inaccessible.html")

	result := &EnumResult{
		GeneratedAt:     time.Date(2026, 7, 6, 8, 0, 0, 0, time.UTC),
		GitLabURL:       "https://gitlab.example.com",
		MinAccessLevel:  int(gitlab.GuestPermissions),
		UsersEnumerated: true,
		Associations: &TokenAssociations{
			Groups: []TokenAssociationGroup{{
				ID:                1,
				Name:              "security-team",
				WebURL:            "https://gitlab.example.com/groups/security-team",
				Visibility:        "private",
				AccessLevels:      30,
				MembersAccessible: false,
				MemberCount:       42,
			}},
			Projects: []TokenAssociationProject{{
				ID:                2,
				NameWithNamespace: "security-team / security-tools",
				WebURL:            "https://gitlab.example.com/security-team/security-tools",
				Visibility:        "private",
				AccessLevels:      TokenAssociationProjectAccess{GroupAccessLevel: 30, ProjectAccessLevel: 0},
				MembersAccessible: false,
				MemberCount:       13,
			}},
		},
	}

	err := WriteHTMLReport(result, output)
	require.NoError(t, err)

	content, err := os.ReadFile(output)
	require.NoError(t, err)

	assert.Equal(t, 2, strings.Count(string(content), "N/A"))
	assert.NotContains(t, string(content), ">42<")
	assert.NotContains(t, string(content), ">13<")
}
