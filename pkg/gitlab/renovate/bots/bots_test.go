package bots

import (
	"testing"

	"github.com/stretchr/testify/assert"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func TestBuildProfileHints(t *testing.T) {
	user := &gitlab.User{
		Username:    "renovate-bot",
		Name:        "Renovate Bot",
		PublicEmail: "renovate-bot@example.com",
		Bot:         true,
	}

	hints := buildProfileHints(user)

	assert.Contains(t, hints, "gitlab_bot_flag=true")
	assert.Contains(t, hints, "name_or_username_contains_renovate")
	assert.Contains(t, hints, "public_email_contains_renovate")
}

func TestBuildActivityHints(t *testing.T) {
	events := []*gitlab.ContributionEvent{
		{
			ActionName:  "pushed",
			Title:       "renovate dependency update",
			TargetTitle: "renovate config update",
			PushData: gitlab.ContributionEventPushData{
				Ref:         "renovate/github.com/pkg/errors-0.x",
				CommitTitle: "chore(deps): update dependency",
			},
		},
	}

	hints := buildActivityHints(events)

	assert.Contains(t, hints, "activity_mentions_renovate")
	assert.Contains(t, hints, "push_to_renovate_branch")
	assert.Contains(t, hints, "renovate_branch_push_activity")
}

func TestUniqueStrings(t *testing.T) {
	input := []string{"a", "a", "", " b ", "b"}
	assert.Equal(t, []string{"a", "b"}, uniqueStrings(input))
}
