package bots

import (
	"errors"
	"strings"
	"sync"

	"github.com/CompassSecurity/pipeleek/pkg/format"
	"github.com/CompassSecurity/pipeleek/pkg/gitlab/util"
	"github.com/rs/zerolog/log"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

const userProcessingConcurrency = 10

func RunEnumerateBots(gitlabURL, token, term string) {
	git, err := util.GetGitlabClient(token, gitlabURL)
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Failed creating gitlab client")
	}

	log.Info().Str("term", term).Msg("Searching GitLab users")

	totalUsers := 0
	potentialBots := 0

	page := 1
	for page != -1 {
		users, nextPage, err := searchUsers(git, term, page)
		if err != nil {
			log.Fatal().Stack().Err(err).Msg("Failed searching users")
		}

		results := make(chan bool, len(users))
		semaphore := make(chan struct{}, userProcessingConcurrency)
		var wg sync.WaitGroup

		for _, user := range users {
			if user == nil {
				continue
			}

			wg.Add(1)
			semaphore <- struct{}{}

			go func(user *gitlab.User) {
				defer wg.Done()
				defer func() { <-semaphore }()

				results <- processUser(git, gitlabURL, user)
			}(user)
		}

		go func() {
			wg.Wait()
			close(results)
		}()

		for likelyBot := range results {
			totalUsers++
			if likelyBot {
				potentialBots++
			}
		}

		page = nextPage
	}

	log.Info().Int("users", totalUsers).Int("potentialBots", potentialBots).Str("term", term).Msg("Renovate bot user enumeration complete")
}

func searchUsers(git *gitlab.Client, term string, page int) ([]*gitlab.User, int, error) {
	opts := &gitlab.ListUsersOptions{
		Search:             gitlab.Ptr(term),
		ExcludeInternal:    gitlab.Ptr(true),
		WithoutProjectBots: gitlab.Ptr(true),
		ListOptions: gitlab.ListOptions{
			PerPage: 100,
			Page:    int64(page),
		},
	}

	users, resp, err := git.Users.ListUsers(opts)
	if err != nil {
		var apiErr *gitlab.ErrorResponse
		if errors.As(err, &apiErr) && (apiErr.HasStatusCode(400) || apiErr.HasStatusCode(403)) {
			log.Debug().Err(err).Msg("ListUsers options ExcludeInternal/WithoutProjectBots not accepted; retrying without them")
			fallbackOpts := &gitlab.ListUsersOptions{
				Search: gitlab.Ptr(term),
				ListOptions: gitlab.ListOptions{
					PerPage: 100,
					Page:    int64(page),
				},
			}

			users, resp, err = git.Users.ListUsers(fallbackOpts)
			if err != nil {
				return nil, -1, err
			}
		} else {
			return nil, -1, err
		}
	}

	nextPage := -1
	if resp != nil && resp.NextPage > 0 {
		nextPage = int(resp.NextPage)
	}

	return users, nextPage, nil
}

func getUserActivity(git *gitlab.Client, userID int64) ([]*gitlab.ContributionEvent, error) {
	events, _, err := git.Users.ListUserContributionEvents(userID, &gitlab.ListContributionEventsOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: 20,
			Page:    1,
		},
	})
	if err != nil {
		var apiErr *gitlab.ErrorResponse
		if errors.As(err, &apiErr) && (apiErr.HasStatusCode(403) || apiErr.HasStatusCode(404)) {
			return nil, nil
		}
		return nil, err
	}

	return events, nil
}

func processUser(git *gitlab.Client, gitlabURL string, user *gitlab.User) bool {
	publicProfile := !user.PrivateProfile

	hints := buildProfileHints(user)

	events, err := getUserActivity(git, user.ID)
	if err != nil {
		log.Debug().Err(err).Str("username", user.Username).Int64("userId", user.ID).Msg("Failed fetching user activity")
	} else {
		hints = append(hints, buildActivityHints(events)...)
	}

	hints = uniqueStrings(hints)
	likelyBot := user.Bot || len(hints) > 0

	profileURL := user.WebURL
	if profileURL == "" {
		profileURL = strings.TrimRight(gitlabURL, "/") + "/" + user.Username
	}

	log.Warn().
		Str("username", user.Username).
		Str("name", user.Name).
		Str("profile", profileURL).
		Bool("publicProfile", publicProfile).
		Bool("botFlag", user.Bot).
		Int("activityEvents", len(events)).
		Bool("likelyRenovateBot", likelyBot).
		Strs("hints", hints).
		Msg("Evaluated GitLab user")

	return likelyBot
}

func buildProfileHints(user *gitlab.User) []string {
	hints := make([]string, 0, 4)

	if user.Bot {
		hints = append(hints, "gitlab_bot_flag=true")
	}

	if format.ContainsI(user.Username, "renovate") || format.ContainsI(user.Name, "renovate") {
		hints = append(hints, "name_or_username_contains_renovate")
	}

	if format.ContainsI(user.PublicEmail, "renovate") {
		hints = append(hints, "public_email_contains_renovate")
	}

	return hints
}

func buildActivityHints(events []*gitlab.ContributionEvent) []string {
	hints := make([]string, 0, 6)

	for _, event := range events {
		if event == nil {
			continue
		}

		if format.ContainsI(event.TargetTitle, "renovate") ||
			format.ContainsI(event.Title, "renovate") ||
			format.ContainsI(event.PushData.Ref, "renovate") ||
			format.ContainsI(event.PushData.CommitTitle, "renovate") {
			hints = append(hints, "activity_mentions_renovate")
		}

		if strings.HasPrefix(strings.ToLower(event.PushData.Ref), "renovate/") {
			hints = append(hints, "push_to_renovate_branch")
		}

		if format.ContainsI(event.ActionName, "push") && format.ContainsI(event.PushData.Ref, "renovate") {
			hints = append(hints, "renovate_branch_push_activity")
		}
	}

	return uniqueStrings(hints)
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))

	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}

	return result
}
