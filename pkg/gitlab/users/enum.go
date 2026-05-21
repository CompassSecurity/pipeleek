package users

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/CompassSecurity/pipeleek/pkg/gitlab/util"
	"github.com/CompassSecurity/pipeleek/pkg/httpclient"
	"github.com/rs/zerolog/log"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

const anonymousEnumerationUnsupportedMsg = "Anonymous GitLab user enumeration is not supported by this instance. Public group and project membership endpoints are also unavailable; use a token for full user enumeration."

var errAnonymousMembersEndpointUnauthorized = errors.New("anonymous members endpoint unauthorized")

type userSource uint8

const (
	userSourceUsersAPI userSource = 1 << iota
	userSourceGroupMembers
	userSourceProjectMembers
)

type enumeratedUser struct {
	ID             int64
	Username       string
	Name           string
	PublicEmail    string
	Profile        string
	State          string
	Bot            bool
	Admin          bool
	External       bool
	PrivateProfile bool
	Sources        userSource
}

type enumeratedUsers struct {
	byID       map[int64]*enumeratedUser
	byUsername map[string]*enumeratedUser
}

type publicEnumerationStats struct {
	groupsListed       int
	projectsListed     int
	groupMemberHits    int
	projectMemberHits  int
	groupsAccessible   bool
	projectsAccessible bool
	groupMembersAccess bool
	projectMembersAccess bool
}

func RunEnum(gitlabURL, token string) {
	git, err := util.GetGitlabClient(token, gitlabURL)
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Failed creating gitlab client")
	}

	log.Info().Msg("Enumerating GitLab users")

	if strings.TrimSpace(token) != "" {
		users, _, err := enumerateUsersViaAPI(git)
		if err != nil {
			log.Fatal().Stack().Err(err).Msg("Failed listing GitLab users")
		}
		logEnumeratedUsers(users)
		log.Info().Int("users", len(users)).Msg("GitLab user enumeration complete")
		return
	}

	users, resp, err := enumerateUsersViaAPI(git)
	if err == nil {
		logEnumeratedUsers(users)
		log.Info().Int("users", len(users)).Msg("GitLab user enumeration complete")
		return
	}

	if !isAnonymousEnumerationUnsupportedWithResponse(err, resp) {
		log.Fatal().Stack().Err(err).Msg("Failed listing GitLab users")
	}

	log.Info().Msg("Anonymous /users enumeration unavailable, falling back to public groups and projects")

	publicUsers, stats, fallbackErr := enumerateUsersFromPublicMembership(git)
	if fallbackErr != nil {
		log.Fatal().Stack().Err(fallbackErr).Msg("Failed enumerating GitLab users from public groups and projects")
	}

	if !stats.groupsAccessible && !stats.projectsAccessible {
		log.Fatal().Msg(anonymousEnumerationUnsupportedMsg)
	}

	if len(publicUsers) == 0 && !stats.groupMembersAccess && !stats.projectMembersAccess {
		log.Fatal().Msg(anonymousEnumerationUnsupportedMsg)
	}

	logEnumeratedUsers(publicUsers)
	log.Info().
		Int("users", len(publicUsers)).
		Int("groups", stats.groupsListed).
		Int("projects", stats.projectsListed).
		Int("groupMemberHits", stats.groupMemberHits).
		Int("projectMemberHits", stats.projectMemberHits).
		Bool("groupMembersAccessible", stats.groupMembersAccess).
		Bool("projectMembersAccessible", stats.projectMembersAccess).
		Msg("GitLab user enumeration complete")
}

// enumerateUsersViaAPI pages through /api/v4/users and returns collected users.
// On error it returns the *gitlab.Response so the caller can inspect the HTTP
// status code directly — even when errors.As cannot unwrap through the HTTP
// client's error chain.
func enumerateUsersViaAPI(git *gitlab.Client) ([]*enumeratedUser, *gitlab.Response, error) {
	allUsers := newEnumeratedUsers()

	page := int64(1)
	for page != -1 {
		users, resp, nextPg, err := listUsers(git, page)
		if err != nil {
			return nil, resp, err
		}

		for _, user := range users {
			entry, isNew := allUsers.addAPIUser(user)
			if isNew {
				logDiscoveredUser(entry, "users_api")
			}
		}

		page = nextPg
	}

	return allUsers.sorted(), nil, nil
}

func enumerateUsersFromPublicMembership(git *gitlab.Client) ([]*enumeratedUser, publicEnumerationStats, error) {
	allUsers := newEnumeratedUsers()
	stats := publicEnumerationStats{}
	gqlClient, graphqlURL := buildGraphQLClient(git)

	if err := collectPublicGroupMembers(git, gqlClient, graphqlURL, allUsers, &stats); err != nil {
		return nil, stats, err
	}

	if err := collectPublicProjectMembers(git, gqlClient, graphqlURL, allUsers, &stats); err != nil {
		return nil, stats, err
	}

	return allUsers.sorted(), stats, nil
}

func collectPublicGroupMembers(git *gitlab.Client, gqlClient *http.Client, graphqlURL string, allUsers *enumeratedUsers, stats *publicEnumerationStats) error {
	visibility := gitlab.PublicVisibility
	page := int64(1)

	for page != -1 {
		groups, resp, err := git.Groups.ListGroups(&gitlab.ListGroupsOptions{
			Visibility: gitlab.Ptr(visibility),
			ListOptions: gitlab.ListOptions{
				PerPage: 100,
				Page:    page,
			},
		})
		if err != nil {
			if isAnonymousEnumerationUnsupportedWithResponse(err, resp) {
				return nil
			}
			return err
		}

		stats.groupsAccessible = true
		log.Debug().Int64("page", page).Int("groupsOnPage", len(groups)).Msg("Enumerating public GitLab groups")

		for index, group := range groups {
			if group == nil {
				continue
			}
			stats.groupsListed++
			log.Debug().
				Int64("page", page).
				Int("indexOnPage", index+1).
				Int64("groupID", group.ID).
				Str("groupName", group.Name).
				Str("groupFullPath", group.FullPath).
				Int("groupsProcessed", stats.groupsListed).
				Msg("Enumerating users from public group")
			if err := collectGroupMembers(git, group.ID, allUsers, stats); err != nil {
				if errors.Is(err, errAnonymousMembersEndpointUnauthorized) {
					log.Debug().Str("groupFullPath", group.FullPath).Msg("Anonymous REST access to group members is denied; trying GraphQL fallback")
					if gqlErr := collectGroupMembersViaGraphQL(gqlClient, graphqlURL, group.FullPath, allUsers, stats); gqlErr != nil {
						return gqlErr
					}
					continue
				}
				return err
			}
		}

		page = nextPage(resp)
	}

	return nil
}

func collectGroupMembers(git *gitlab.Client, groupID int64, allUsers *enumeratedUsers, stats *publicEnumerationStats) error {
	page := int64(1)

	for page != -1 {
		opt := &gitlab.ListGroupMembersOptions{
			ListOptions: gitlab.ListOptions{
				PerPage: 100,
				Page:    page,
			},
		}

		members, resp, err := git.Groups.ListAllGroupMembers(groupID, opt)
		if err != nil && isAllMembersEndpointUnavailable(err, resp) {
			members, resp, err = git.Groups.ListGroupMembers(groupID, opt)
		}
		if err != nil {
			if isAnonymousEnumerationUnsupportedWithResponse(err, resp) {
				return errAnonymousMembersEndpointUnauthorized
			}
			return err
		}

		stats.groupMembersAccess = true

		for _, member := range members {
			entry, isNew := allUsers.addGroupMember(member)
			if isNew {
				logDiscoveredUser(entry, "public_group_members")
			}
			if member != nil {
				stats.groupMemberHits++
			}
		}

		page = nextPage(resp)
	}

	return nil
}

func collectPublicProjectMembers(git *gitlab.Client, gqlClient *http.Client, graphqlURL string, allUsers *enumeratedUsers, stats *publicEnumerationStats) error {
	visibility := gitlab.PublicVisibility
	page := int64(1)

	for page != -1 {
		projects, resp, err := git.Projects.ListProjects(&gitlab.ListProjectsOptions{
			Visibility: gitlab.Ptr(visibility),
			Simple:     gitlab.Ptr(true),
			ListOptions: gitlab.ListOptions{
				PerPage: 100,
				Page:    page,
			},
		})
		if err != nil {
			if isAnonymousEnumerationUnsupportedWithResponse(err, resp) {
				return nil
			}
			return err
		}

		stats.projectsAccessible = true
		log.Debug().Int64("page", page).Int("projectsOnPage", len(projects)).Msg("Enumerating public GitLab projects")

		for index, project := range projects {
			if project == nil {
				continue
			}
			stats.projectsListed++
			log.Debug().
				Int64("page", page).
				Int("indexOnPage", index+1).
				Int64("projectID", project.ID).
				Str("projectName", project.Name).
				Str("projectPathWithNamespace", project.PathWithNamespace).
				Int("projectsProcessed", stats.projectsListed).
				Msg("Enumerating users from public project")
			if err := collectProjectMembers(git, project.ID, allUsers, stats); err != nil {
				if errors.Is(err, errAnonymousMembersEndpointUnauthorized) {
					log.Debug().Str("projectPathWithNamespace", project.PathWithNamespace).Msg("Anonymous REST access to project members is denied; trying GraphQL fallback")
					if gqlErr := collectProjectMembersViaGraphQL(gqlClient, graphqlURL, project.PathWithNamespace, allUsers, stats); gqlErr != nil {
						return gqlErr
					}
					continue
				}
				return err
			}
		}

		page = nextPage(resp)
	}

	return nil
}

func collectProjectMembers(git *gitlab.Client, projectID int64, allUsers *enumeratedUsers, stats *publicEnumerationStats) error {
	page := int64(1)

	for page != -1 {
		opt := &gitlab.ListProjectMembersOptions{
			ListOptions: gitlab.ListOptions{
				PerPage: 100,
				Page:    page,
			},
		}

		members, resp, err := git.ProjectMembers.ListAllProjectMembers(projectID, opt)
		if err != nil && isAllMembersEndpointUnavailable(err, resp) {
			members, resp, err = git.ProjectMembers.ListProjectMembers(projectID, opt)
		}
		if err != nil {
			if isAnonymousEnumerationUnsupportedWithResponse(err, resp) {
				return errAnonymousMembersEndpointUnauthorized
			}
			return err
		}

		stats.projectMembersAccess = true

		for _, member := range members {
			entry, isNew := allUsers.addProjectMember(member)
			if isNew {
				logDiscoveredUser(entry, "public_project_members")
			}
			if member != nil {
				stats.projectMemberHits++
			}
		}

		page = nextPage(resp)
	}

	return nil
}

type graphQLResponse struct {
	Data   graphQLData    `json:"data"`
	Errors []graphQLError `json:"errors"`
}

type graphQLError struct {
	Message string `json:"message"`
}

type graphQLData struct {
	Group   *graphQLGroup   `json:"group"`
	Project *graphQLProject `json:"project"`
}

type graphQLGroup struct {
	GroupMembers graphQLMembersConnection `json:"groupMembers"`
}

type graphQLProject struct {
	ProjectMembers graphQLMembersConnection `json:"projectMembers"`
}

type graphQLMembersConnection struct {
	Nodes    []graphQLMemberNode `json:"nodes"`
	PageInfo graphQLPageInfo     `json:"pageInfo"`
}

type graphQLMemberNode struct {
	User *graphQLUser `json:"user"`
}

type graphQLUser struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	Name        string `json:"name"`
	PublicEmail string `json:"publicEmail"`
	WebURL      string `json:"webUrl"`
	State       string `json:"state"`
}

type graphQLPageInfo struct {
	HasNextPage bool   `json:"hasNextPage"`
	EndCursor   string `json:"endCursor"`
}

func collectGroupMembersViaGraphQL(client *http.Client, graphqlURL, groupFullPath string, allUsers *enumeratedUsers, stats *publicEnumerationStats) error {
	if strings.TrimSpace(groupFullPath) == "" {
		return nil
	}

	query := `query($fullPath: ID!, $first: Int!, $after: String) {
  group(fullPath: $fullPath) {
    groupMembers(first: $first, after: $after) {
      nodes {
        user {
					id
          username
          name
          publicEmail
          webUrl
          state
        }
      }
      pageInfo {
        hasNextPage
        endCursor
      }
    }
  }
}`

	after := ""
	for {
		resp, err := doGraphQLRequest(client, graphqlURL, query, map[string]any{
			"fullPath": groupFullPath,
			"first":    100,
			"after":    nullableCursor(after),
		})
		if err != nil {
			return err
		}

		if len(resp.Errors) > 0 {
			return fmt.Errorf("group members graphql query failed: %s", resp.Errors[0].Message)
		}

		if resp.Data.Group == nil {
			return nil
		}

		stats.groupMembersAccess = true

		for _, node := range resp.Data.Group.GroupMembers.Nodes {
			if node.User == nil {
				continue
			}
			entry, isNew := allUsers.addGroupMember(&gitlab.GroupMember{
				ID:          parseGraphQLUserID(node.User.ID),
				Username:    node.User.Username,
				Name:        node.User.Name,
				PublicEmail: node.User.PublicEmail,
				WebURL:      node.User.WebURL,
				State:       node.User.State,
			})
			stats.groupMemberHits++
			if isNew {
				logDiscoveredUser(entry, "public_group_members")
			}
		}

		if !resp.Data.Group.GroupMembers.PageInfo.HasNextPage {
			break
		}
		after = resp.Data.Group.GroupMembers.PageInfo.EndCursor
	}

	return nil
}

func collectProjectMembersViaGraphQL(client *http.Client, graphqlURL, projectPathWithNamespace string, allUsers *enumeratedUsers, stats *publicEnumerationStats) error {
	if strings.TrimSpace(projectPathWithNamespace) == "" {
		return nil
	}

	query := `query($fullPath: ID!, $first: Int!, $after: String) {
  project(fullPath: $fullPath) {
    projectMembers(first: $first, after: $after) {
      nodes {
        user {
					id
          username
          name
          publicEmail
          webUrl
          state
        }
      }
      pageInfo {
        hasNextPage
        endCursor
      }
    }
  }
}`

	after := ""
	for {
		resp, err := doGraphQLRequest(client, graphqlURL, query, map[string]any{
			"fullPath": projectPathWithNamespace,
			"first":    100,
			"after":    nullableCursor(after),
		})
		if err != nil {
			return err
		}

		if len(resp.Errors) > 0 {
			return fmt.Errorf("project members graphql query failed: %s", resp.Errors[0].Message)
		}

		if resp.Data.Project == nil {
			return nil
		}

		stats.projectMembersAccess = true

		for _, node := range resp.Data.Project.ProjectMembers.Nodes {
			if node.User == nil {
				continue
			}
			entry, isNew := allUsers.addProjectMember(&gitlab.ProjectMember{
				ID:       parseGraphQLUserID(node.User.ID),
				Username: node.User.Username,
				Email:    node.User.PublicEmail,
				Name:     node.User.Name,
				WebURL:   node.User.WebURL,
				State:    node.User.State,
			})
			stats.projectMemberHits++
			if isNew {
				logDiscoveredUser(entry, "public_project_members")
			}
		}

		if !resp.Data.Project.ProjectMembers.PageInfo.HasNextPage {
			break
		}
		after = resp.Data.Project.ProjectMembers.PageInfo.EndCursor
	}

	return nil
}

func buildGraphQLClient(git *gitlab.Client) (*http.Client, string) {
	apiBase := strings.TrimRight(git.BaseURL().String(), "/")
	graphqlURL := strings.TrimSuffix(apiBase, "/api/v4") + "/api/graphql"
	client := httpclient.GetPipeleekHTTPClient(apiBase, nil, nil).StandardClient()
	return client, graphqlURL
}

func doGraphQLRequest(client *http.Client, graphqlURL, query string, variables map[string]any) (*graphQLResponse, error) {

	body, err := json.Marshal(map[string]any{
		"query":     query,
		"variables": variables,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, graphqlURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("graphql request failed with status %d", resp.StatusCode)
	}

	var decoded graphQLResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return nil, err
	}

	return &decoded, nil
}

func nullableCursor(cursor string) any {
	if strings.TrimSpace(cursor) == "" {
		return nil
	}
	return cursor
}

func parseGraphQLUserID(id string) int64 {
	trimmed := strings.TrimSpace(id)
	if trimmed == "" {
		return 0
	}

	if parsed, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
		return parsed
	}

	lastSlash := strings.LastIndex(trimmed, "/")
	if lastSlash == -1 || lastSlash == len(trimmed)-1 {
		return 0
	}

	parsed, err := strconv.ParseInt(trimmed[lastSlash+1:], 10, 64)
	if err != nil {
		return 0
	}

	return parsed
}

// listUsers fetches a single page of /api/v4/users. It always returns the
// *gitlab.Response even on error so callers can inspect the HTTP status code
// directly, bypassing any error-chain wrapping introduced by the HTTP client.
func listUsers(git *gitlab.Client, page int64) ([]*gitlab.User, *gitlab.Response, int64, error) {
	users, resp, err := git.Users.ListUsers(&gitlab.ListUsersOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: 100,
			Page:    page,
		},
	})
	if err != nil {
		return nil, resp, -1, err
	}

	return users, resp, nextPage(resp), nil
}

func newEnumeratedUsers() *enumeratedUsers {
	return &enumeratedUsers{
		byID:       make(map[int64]*enumeratedUser),
		byUsername: make(map[string]*enumeratedUser),
	}
}

func (users *enumeratedUsers) addAPIUser(user *gitlab.User) (*enumeratedUser, bool) {
	if user == nil {
		return nil, false
	}
	entry, created := users.upsert(user.ID, user.Username)
	mergeCommonFields(entry, user.Name, user.PublicEmail, user.WebURL, user.State)
	entry.Bot = entry.Bot || user.Bot
	entry.Admin = entry.Admin || user.IsAdmin
	entry.External = entry.External || user.External
	entry.PrivateProfile = entry.PrivateProfile || user.PrivateProfile
	entry.Sources |= userSourceUsersAPI
	if entry.Username == "" {
		entry.Username = user.Username
	}
	if entry.ID == 0 {
		entry.ID = user.ID
	}

	return entry, created
}

func (users *enumeratedUsers) addGroupMember(member *gitlab.GroupMember) (*enumeratedUser, bool) {
	if member == nil {
		return nil, false
	}
	entry, created := users.upsert(member.ID, member.Username)
	mergeCommonFields(entry, member.Name, member.PublicEmail, member.WebURL, member.State)
	entry.Sources |= userSourceGroupMembers
	if entry.Username == "" {
		entry.Username = member.Username
	}
	if entry.ID == 0 {
		entry.ID = member.ID
	}

	return entry, created
}

func (users *enumeratedUsers) addProjectMember(member *gitlab.ProjectMember) (*enumeratedUser, bool) {
	if member == nil {
		return nil, false
	}
	entry, created := users.upsert(member.ID, member.Username)
	mergeCommonFields(entry, member.Name, member.Email, member.WebURL, member.State)
	entry.Sources |= userSourceProjectMembers
	if entry.Username == "" {
		entry.Username = member.Username
	}
	if entry.ID == 0 {
		entry.ID = member.ID
	}

	return entry, created
}

// upsert finds an existing entry by ID (preferred) then by normalised username,
// or creates a new one. O(1) average via map lookups.
func (users *enumeratedUsers) upsert(id int64, username string) (*enumeratedUser, bool) {
	normalizedUsername := normalizeUsername(username)

	if id > 0 {
		if existing, ok := users.byID[id]; ok {
			if normalizedUsername != "" {
				users.byUsername[normalizedUsername] = existing
			}
			return existing, false
		}
	}

	if normalizedUsername != "" {
		if existing, ok := users.byUsername[normalizedUsername]; ok {
			if id > 0 {
				users.byID[id] = existing
				if existing.ID == 0 {
					existing.ID = id
				}
			}
			return existing, false
		}
	}

	entry := &enumeratedUser{ID: id, Username: username}
	if id > 0 {
		users.byID[id] = entry
	}
	if normalizedUsername != "" {
		users.byUsername[normalizedUsername] = entry
	}

	return entry, true
}

// sorted returns a deduplicated, sorted slice of users. Dedup uses pointer
// identity so entries referenced by both byID and byUsername appear only once.
func (users *enumeratedUsers) sorted() []*enumeratedUser {
	seen := make(map[*enumeratedUser]struct{}, len(users.byID)+len(users.byUsername))
	result := make([]*enumeratedUser, 0, len(users.byID)+len(users.byUsername))

	for _, user := range users.byID {
		if _, ok := seen[user]; !ok {
			seen[user] = struct{}{}
			result = append(result, user)
		}
	}

	for _, user := range users.byUsername {
		if _, ok := seen[user]; !ok {
			seen[user] = struct{}{}
			result = append(result, user)
		}
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].ID != result[j].ID {
			return result[i].ID < result[j].ID
		}
		return result[i].Username < result[j].Username
	})

	return result
}

func logEnumeratedUsers(users []*enumeratedUser) {
	for _, user := range users {
		if user == nil {
			continue
		}
		knownFromUsersAPI := user.Sources&userSourceUsersAPI != 0
		event := log.Info().
			Int64("id", user.ID).
			Str("username", user.Username).
			Str("name", user.Name).
			Str("publicEmail", user.PublicEmail).
			Str("profile", user.Profile).
			Str("state", user.State).
			Strs("sources", user.sourceNames())

		if knownFromUsersAPI {
			event = event.
				Bool("bot", user.Bot).
				Bool("admin", user.Admin).
				Bool("external", user.External).
				Bool("privateProfile", user.PrivateProfile)
		}

		event.Msg("GitLab user")
	}
}

func logDiscoveredUser(user *enumeratedUser, source string) {
	if user == nil {
		return
	}

	knownFromUsersAPI := user.Sources&userSourceUsersAPI != 0

	event := log.Info().
		Int64("id", user.ID).
		Str("username", user.Username).
		Str("name", user.Name).
		Str("publicEmail", user.PublicEmail).
		Str("profile", user.Profile).
		Str("state", user.State).
		Str("source", source)

	if knownFromUsersAPI {
		event = event.
			Bool("bot", user.Bot).
			Bool("admin", user.Admin).
			Bool("external", user.External).
			Bool("privateProfile", user.PrivateProfile)
	}

	event.Msg("User")
}

func mergeCommonFields(user *enumeratedUser, name, publicEmail, profile, state string) {
	if user.Name == "" {
		user.Name = name
	}
	if user.PublicEmail == "" {
		user.PublicEmail = publicEmail
	}
	if user.Profile == "" {
		user.Profile = profile
	}
	if user.State == "" {
		user.State = state
	}
}

func (user *enumeratedUser) sourceNames() []string {
	sources := make([]string, 0, 3)
	if user.Sources&userSourceUsersAPI != 0 {
		sources = append(sources, "users_api")
	}
	if user.Sources&userSourceGroupMembers != 0 {
		sources = append(sources, "public_group_members")
	}
	if user.Sources&userSourceProjectMembers != 0 {
		sources = append(sources, "public_project_members")
	}
	return sources
}

func normalizeUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

func nextPage(resp *gitlab.Response) int64 {
	if resp != nil && resp.NextPage > 0 {
		return resp.NextPage
	}
	return -1
}

func isAllMembersEndpointUnavailable(err error, resp *gitlab.Response) bool {
	if resp != nil && (resp.StatusCode == 404 || resp.StatusCode == 405) {
		return true
	}

	var apiErr *gitlab.ErrorResponse
	if errors.As(err, &apiErr) {
		if apiErr.HasStatusCode(404) || apiErr.HasStatusCode(405) {
			return true
		}
		if apiErr.Response != nil && (apiErr.Response.StatusCode == 404 || apiErr.Response.StatusCode == 405) {
			return true
		}
	}

	return false
}

// isAnonymousEnumerationUnsupportedWithResponse returns true when the error (or
// response status) indicates that anonymous enumeration is rejected (401/403).
// Checking resp.StatusCode directly is preferred because the HTTP client may
// wrap errors in ways that prevent errors.As from finding *gitlab.ErrorResponse.
func isAnonymousEnumerationUnsupportedWithResponse(err error, resp *gitlab.Response) bool {
	if resp != nil && (resp.StatusCode == 401 || resp.StatusCode == 403) {
		return true
	}

	var apiErr *gitlab.ErrorResponse
	if errors.As(err, &apiErr) {
		if apiErr.HasStatusCode(401) || apiErr.HasStatusCode(403) {
			return true
		}
		if apiErr.Response != nil && (apiErr.Response.StatusCode == 401 || apiErr.Response.StatusCode == 403) {
			return true
		}
	}

	return false
}
