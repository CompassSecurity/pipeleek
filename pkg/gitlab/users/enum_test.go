package users

import (
	"testing"

	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func TestEnumeratedUsersDedupesByIDAcrossSources(t *testing.T) {
	users := newEnumeratedUsers()

	users.addGroupMember(&gitlab.GroupMember{
		ID:          7,
		Username:    "alice",
		Name:        "Alice Example",
		PublicEmail: "alice@example.com",
		WebURL:      "https://gitlab.example.com/alice",
		State:       "active",
	})
	users.addProjectMember(&gitlab.ProjectMember{
		ID:       7,
		Username: "alice",
		Name:     "Alice Example",
		WebURL:   "https://gitlab.example.com/alice",
		State:    "active",
	})

	result := users.sorted()
	if len(result) != 1 {
		t.Fatalf("expected 1 unique user, got %d", len(result))
	}

	if result[0].PublicEmail != "alice@example.com" {
		t.Fatalf("expected public email to be preserved, got %q", result[0].PublicEmail)
	}

	if got := result[0].sourceNames(); len(got) != 2 || got[0] != "public_group_members" || got[1] != "public_project_members" {
		t.Fatalf("unexpected sources: %#v", got)
	}
}

func TestEnumeratedUsersDedupesByUsernameWhenIDMissing(t *testing.T) {
	users := newEnumeratedUsers()

	users.addProjectMember(&gitlab.ProjectMember{
		Username: "Bob",
		Name:     "Bob Example",
	})
	users.addGroupMember(&gitlab.GroupMember{
		ID:       13,
		Username: "bob",
		Name:     "Bob Example",
		WebURL:   "https://gitlab.example.com/bob",
	})

	result := users.sorted()
	if len(result) != 1 {
		t.Fatalf("expected 1 unique user, got %d", len(result))
	}

	if result[0].ID != 13 {
		t.Fatalf("expected missing ID to be backfilled, got %d", result[0].ID)
	}

	if result[0].Profile != "https://gitlab.example.com/bob" {
		t.Fatalf("expected profile to be merged, got %q", result[0].Profile)
	}
}

func TestParseGraphQLUserID(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int64
	}{
		{name: "empty", input: "", want: 0},
		{name: "numeric", input: "123", want: 123},
		{name: "global id", input: "gid://gitlab/User/456", want: 456},
		{name: "invalid", input: "gid://gitlab/User/not-a-number", want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseGraphQLUserID(tt.input)
			if got != tt.want {
				t.Fatalf("parseGraphQLUserID(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}