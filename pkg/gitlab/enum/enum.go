package enum

import (
	"errors"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	gitlabutil "github.com/CompassSecurity/pipeleek/pkg/gitlab/util"
	"github.com/CompassSecurity/pipeleek/pkg/httpclient"
	"github.com/rs/zerolog/log"
	gitlab "gitlab.com/gitlab-org/api/client-go"

	"resty.dev/v3"
)

// ExportOptions controls optional enum artifact generation.
type ExportOptions struct {
	HTMLReportPath string
	EnumerateUsers bool
}

// EnumResult contains collected user, token and access association data.
type EnumResult struct {
	GeneratedAt     time.Time          `json:"generated_at"`
	GitLabURL       string             `json:"gitlab_url"`
	MinAccessLevel  int                `json:"min_access_level"`
	UsersEnumerated bool               `json:"users_enumerated"`
	User            *gitlab.User       `json:"user"`
	Users           []*gitlab.User     `json:"users"`
	Token           *SelfToken         `json:"token"`
	Associations    *TokenAssociations `json:"associations"`
}

func effectiveProjectAccessLevels(groupAccessLevel int, projectAccessLevel int) (effective int, inherited bool) {
	effective = projectAccessLevel
	if groupAccessLevel > effective {
		effective = groupAccessLevel
	}

	return effective, projectAccessLevel < effective
}

// RunEnum performs the enumeration of GitLab access rights
func RunEnum(gitlabUrl, gitlabApiToken string, minAccessLevel int) {
	RunEnumWithOptions(gitlabUrl, gitlabApiToken, minAccessLevel, ExportOptions{})
}

// RunEnumWithOptions performs enumeration and optionally writes export artifacts.
func RunEnumWithOptions(gitlabUrl, gitlabApiToken string, minAccessLevel int, opts ExportOptions) {
	result := collectEnumData(gitlabUrl, gitlabApiToken, minAccessLevel, opts.EnumerateUsers)
	logEnumResult(result)

	if opts.HTMLReportPath != "" {
		if err := WriteHTMLReport(result, opts.HTMLReportPath); err != nil {
			log.Fatal().Stack().Err(err).Str("path", opts.HTMLReportPath).Msg("Failed writing enum HTML report")
		}
		log.Info().Str("path", opts.HTMLReportPath).Msg("Wrote enum HTML report")
	}

	log.Info().Msg("Done")
}

func collectEnumData(gitlabUrl, gitlabApiToken string, minAccessLevel int, enumerateUsers bool) *EnumResult {
	git, err := gitlabutil.GetGitlabClient(gitlabApiToken, gitlabUrl)
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Failed creating gitlab client")
	}

	user, _, err := git.Users.CurrentUser()

	if err != nil {
		log.Fatal().Stack().Err(err).Msg("failed fetching current user")
	}

	client := *httpclient.GetPipeleekHTTPClient("", nil, nil).SetRedirectPolicy(resty.RedirectFlexiblePolicy(5))
	token := fetchCurrentToken(client, gitlabUrl, gitlabApiToken)

	associations := &TokenAssociations{}
	page := 1
	log.Info().Msg("Collecting token associations")
	for page != -1 {
		log.Debug().Int("page", page).Msg("Requesting token association page")
		batch, nextPage := fetchTokenAssociationsPage(client, gitlabUrl, gitlabApiToken, minAccessLevel, page)
		if batch != nil {
			log.Info().Int("page", page).Int("groups", len(batch.Groups)).Int("projects", len(batch.Projects)).Msg("Fetched token association page")
			associations.Groups = append(associations.Groups, batch.Groups...)
			associations.Projects = append(associations.Projects, batch.Projects...)
			for _, group := range batch.Groups {
				log.Warn().
					Str("group", group.WebURL).
					Str("accessLevel", gitlabutil.AccessLevelName(gitlab.AccessLevelValue(group.AccessLevels))).
					Str("name", group.Name).
					Str("visibility", string(group.Visibility)).
					Msg("Group")
			}

			for _, project := range batch.Projects {
				effective, inherited := effectiveProjectAccessLevels(project.AccessLevels.GroupAccessLevel, project.AccessLevels.ProjectAccessLevel)
				log.Warn().
					Str("project", project.WebURL).
					Str("name", project.NameWithNamespace).
					Str("groupAccessLevel", gitlabutil.AccessLevelName(gitlab.AccessLevelValue(project.AccessLevels.GroupAccessLevel))).
					Str("projectAccessLevel", gitlabutil.AccessLevelName(gitlab.AccessLevelValue(project.AccessLevels.ProjectAccessLevel))).
					Str("effectiveAccessLevel", gitlabutil.AccessLevelName(gitlab.AccessLevelValue(effective))).
					Bool("accessInheritedFromGroup", inherited).
					Msg("Project")
			}
		}
		page = nextPage
	}

	users := make([]*gitlab.User, 0)
	if enumerateUsers {
		log.Info().Msg("Collecting scoped members from discovered groups and projects")
		fetchedUsers, fetchErr := collectScopedUsersFromAssociations(git, associations)
		if fetchErr != nil {
			log.Warn().Err(fetchErr).Msg("Failed enumerating users from associated groups/projects; continuing without users section data")
		} else {
			users = fetchedUsers
		}
	}

	return &EnumResult{
		GeneratedAt:     time.Now().UTC(),
		GitLabURL:       gitlabUrl,
		MinAccessLevel:  minAccessLevel,
		UsersEnumerated: enumerateUsers,
		User:            user,
		Users:           users,
		Token:           token,
		Associations:    associations,
	}
}

func logEnumResult(result *EnumResult) {

	log.Info().Msg("Enumerating User")
	log.Warn().Str("username", result.User.Username).Str("name", result.User.Name).Str("email", result.User.Email).Bool("admin", result.User.IsAdmin).Bool("bot", result.User.Bot).Msg("Current user")
	log.Debug().Interface("full_user", result.User).Msg("Full User details")

	log.Info().Msg("Enumerating Access Token")
	if result.Token != nil {
		log.Warn().
			Int("id", result.Token.ID).
			Str("name", result.Token.Name).
			Bool("revoked", result.Token.Revoked).
			Time("created", result.Token.CreatedAt).
			Str("description", result.Token.Description).
			Str("scopes", strings.Join(result.Token.Scopes, ",")).
			Int("userId", result.Token.UserID).
			Time("lastUsedAt", result.Token.LastUsedAt).
			Bool("active", result.Token.Active).
			Str("lastUsedIps", strings.Join(result.Token.LastUsedIps, ",")).
			Msg("Current Token")
		log.Debug().Interface("full_token", result.Token).Msg("Full Token details")
	}

	log.Info().Msg("Enumerating Projects and Groups")
	log.Info().Int("groups", len(result.Associations.Groups)).Int("projects", len(result.Associations.Projects)).Msg("Enumerated projects and groups")

	if result.UsersEnumerated {
		log.Info().Int("users", len(result.Users)).Msg("Enumerated related users from associated groups/projects")
	}
}

func collectScopedUsersFromAssociations(git *gitlab.Client, associations *TokenAssociations) ([]*gitlab.User, error) {
	usersByID := make(map[int64]*gitlab.User)
	usersByUsername := make(map[string]*gitlab.User)

	for i := range associations.Groups {
		group := &associations.Groups[i]
		log.Info().Int("groupId", group.ID).Str("group", group.Name).Msg("Enumerating group members")
		members, accessible, err := fetchGroupMembers(git, int64(group.ID))
		group.MembersEnumerated = true
		group.MembersAccessible = accessible
		if err != nil {
			group.MembersError = err.Error()
			log.Warn().Err(err).Int("groupId", group.ID).Str("group", group.Name).Msg("Failed enumerating group members")
			continue
		}
		group.Members = members
		group.MemberCount = len(members)
		log.Info().Int("groupId", group.ID).Str("group", group.Name).Int("members", group.MemberCount).Msg("Enumerated group members")

		for _, member := range members {
			addScopedMemberUser(usersByID, usersByUsername, member)
		}
	}

	for i := range associations.Projects {
		project := &associations.Projects[i]
		log.Info().Int("projectId", project.ID).Str("project", project.NameWithNamespace).Msg("Enumerating project members")
		members, accessible, err := fetchProjectMembers(git, int64(project.ID))
		project.MembersEnumerated = true
		project.MembersAccessible = accessible
		if err != nil {
			project.MembersError = err.Error()
			log.Warn().Err(err).Int("projectId", project.ID).Str("project", project.NameWithNamespace).Msg("Failed enumerating project members")
			continue
		}
		project.Members = members
		project.MemberCount = len(members)
		log.Info().Int("projectId", project.ID).Str("project", project.NameWithNamespace).Int("members", project.MemberCount).Msg("Enumerated project members")

		for _, member := range members {
			addScopedMemberUser(usersByID, usersByUsername, member)
		}
	}

	users := make([]*gitlab.User, 0, len(usersByID)+len(usersByUsername))
	for _, user := range usersByID {
		users = append(users, user)
	}
	for _, user := range usersByUsername {
		if user == nil {
			continue
		}
		if user.ID > 0 {
			continue
		}
		users = append(users, user)
	}

	sort.Slice(users, func(i, j int) bool {
		if users[i].ID != users[j].ID {
			return users[i].ID < users[j].ID
		}
		return strings.ToLower(users[i].Username) < strings.ToLower(users[j].Username)
	})

	return users, nil
}

func addScopedMemberUser(usersByID map[int64]*gitlab.User, usersByUsername map[string]*gitlab.User, member TokenAssociationMember) {
	user := &gitlab.User{
		ID:          member.ID,
		Username:    member.Username,
		Name:        member.Name,
		PublicEmail: member.Email,
		Email:       member.Email,
		WebURL:      member.WebURL,
		State:       member.State,
	}

	if user.ID > 0 {
		usersByID[user.ID] = user
		if user.Username != "" {
			usersByUsername[strings.ToLower(user.Username)] = user
		}
		return
	}

	if user.Username != "" {
		usersByUsername[strings.ToLower(user.Username)] = user
	}
}

func fetchGroupMembers(git *gitlab.Client, groupID int64) ([]TokenAssociationMember, bool, error) {
	results := make([]TokenAssociationMember, 0)
	page := int64(1)
	accessible := false

	for page != -1 {
		log.Debug().Int64("groupId", groupID).Int64("page", page).Msg("Requesting group members page")
		opt := &gitlab.ListGroupMembersOptions{
			ListOptions: gitlab.ListOptions{
				PerPage: 100,
				Page:    page,
			},
		}

		members, resp, err := git.Groups.ListAllGroupMembers(groupID, opt)
		if err != nil && isMembersEndpointUnsupported(err, resp) {
			log.Debug().Int64("groupId", groupID).Msg("ListAllGroupMembers unsupported, falling back to ListGroupMembers")
			members, resp, err = git.Groups.ListGroupMembers(groupID, opt)
		}
		if err != nil {
			if isMembersEndpointUnsupported(err, resp) {
				return nil, false, nil
			}
			return nil, false, err
		}

		accessible = true
		for _, member := range members {
			if member == nil {
				continue
			}
			results = append(results, TokenAssociationMember{
				ID:          member.ID,
				Username:    member.Username,
				Name:        member.Name,
				Email:       member.PublicEmail,
				WebURL:      member.WebURL,
				State:       member.State,
				AccessLevel: int(member.AccessLevel),
			})
		}
		log.Debug().Int64("groupId", groupID).Int64("page", page).Int("membersOnPage", len(members)).Int("membersCollected", len(results)).Msg("Processed group members page")

		page = nextPage(resp)
	}

	return results, accessible, nil
}

func fetchProjectMembers(git *gitlab.Client, projectID int64) ([]TokenAssociationMember, bool, error) {
	results := make([]TokenAssociationMember, 0)
	page := int64(1)
	accessible := false

	for page != -1 {
		log.Debug().Int64("projectId", projectID).Int64("page", page).Msg("Requesting project members page")
		opt := &gitlab.ListProjectMembersOptions{
			ListOptions: gitlab.ListOptions{
				PerPage: 100,
				Page:    page,
			},
		}

		members, resp, err := git.ProjectMembers.ListAllProjectMembers(projectID, opt)
		if err != nil && isMembersEndpointUnsupported(err, resp) {
			log.Debug().Int64("projectId", projectID).Msg("ListAllProjectMembers unsupported, falling back to ListProjectMembers")
			members, resp, err = git.ProjectMembers.ListProjectMembers(projectID, opt)
		}
		if err != nil {
			if isMembersEndpointUnsupported(err, resp) {
				return nil, false, nil
			}
			return nil, false, err
		}

		accessible = true
		for _, member := range members {
			if member == nil {
				continue
			}
			results = append(results, TokenAssociationMember{
				ID:          member.ID,
				Username:    member.Username,
				Name:        member.Name,
				Email:       member.Email,
				WebURL:      member.WebURL,
				State:       member.State,
				AccessLevel: int(member.AccessLevel),
			})
		}
		log.Debug().Int64("projectId", projectID).Int64("page", page).Int("membersOnPage", len(members)).Int("membersCollected", len(results)).Msg("Processed project members page")

		page = nextPage(resp)
	}

	return results, accessible, nil
}

func nextPage(resp *gitlab.Response) int64 {
	if resp != nil && resp.NextPage > 0 {
		return resp.NextPage
	}
	return -1
}

func isMembersEndpointUnsupported(err error, resp *gitlab.Response) bool {
	if resp != nil && (resp.StatusCode == 404 || resp.StatusCode == 405) {
		return true
	}

	var apiErr *gitlab.ErrorResponse
	if errors.As(err, &apiErr) {
		if apiErr.HasStatusCode(404) || apiErr.HasStatusCode(405) {
			return true
		}
		if apiErr.Response != nil {
			statusCode := apiErr.Response.StatusCode
			if statusCode == 404 || statusCode == 405 {
				return true
			}
		}
	}

	return false
}

type TokenAssociations struct {
	Groups   []TokenAssociationGroup   `json:"groups"`
	Projects []TokenAssociationProject `json:"projects"`
}

type TokenAssociationGroup struct {
	ID                int                      `json:"id"`
	WebURL            string                   `json:"web_url"`
	Name              string                   `json:"name"`
	ParentID          interface{}              `json:"parent_id"`
	OrganizationID    int                      `json:"organization_id"`
	AccessLevels      int                      `json:"access_levels"`
	Visibility        string                   `json:"visibility"`
	Members           []TokenAssociationMember `json:"members,omitempty"`
	MembersEnumerated bool                     `json:"members_enumerated,omitempty"`
	MembersAccessible bool                     `json:"members_accessible,omitempty"`
	MembersError      string                   `json:"members_error,omitempty"`
	MemberCount       int                      `json:"member_count,omitempty"`
}

type TokenAssociationMember struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	Name        string `json:"name"`
	Email       string `json:"email"`
	WebURL      string `json:"web_url"`
	State       string `json:"state"`
	AccessLevel int    `json:"access_level"`
}

type TokenAssociationProject struct {
	ID                int                              `json:"id"`
	Description       string                           `json:"description"`
	Name              string                           `json:"name"`
	NameWithNamespace string                           `json:"name_with_namespace"`
	Path              string                           `json:"path"`
	PathWithNamespace string                           `json:"path_with_namespace"`
	CreatedAt         time.Time                        `json:"created_at"`
	AccessLevels      TokenAssociationProjectAccess    `json:"access_levels"`
	Visibility        string                           `json:"visibility"`
	WebURL            string                           `json:"web_url"`
	Namespace         TokenAssociationProjectNamespace `json:"namespace"`
	Members           []TokenAssociationMember         `json:"members,omitempty"`
	MembersEnumerated bool                             `json:"members_enumerated,omitempty"`
	MembersAccessible bool                             `json:"members_accessible,omitempty"`
	MembersError      string                           `json:"members_error,omitempty"`
	MemberCount       int                              `json:"member_count,omitempty"`
}

type TokenAssociationProjectAccess struct {
	ProjectAccessLevel int `json:"project_access_level"`
	GroupAccessLevel   int `json:"group_access_level"`
}

type TokenAssociationProjectNamespace struct {
	ID        int         `json:"id"`
	Name      string      `json:"name"`
	Path      string      `json:"path"`
	Kind      string      `json:"kind"`
	FullPath  string      `json:"full_path"`
	ParentID  interface{} `json:"parent_id"`
	AvatarURL string      `json:"avatar_url"`
	WebURL    string      `json:"web_url"`
}

type SelfToken struct {
	ID          int       `json:"id"`
	Name        string    `json:"name"`
	Revoked     bool      `json:"revoked"`
	CreatedAt   time.Time `json:"created_at"`
	Description string    `json:"description"`
	Scopes      []string  `json:"scopes"`
	UserID      int       `json:"user_id"`
	LastUsedAt  time.Time `json:"last_used_at"`
	Active      bool      `json:"active"`
	ExpiresAt   string    `json:"expires_at"`
	LastUsedIps []string  `json:"last_used_ips"`
}

func fetchCurrentToken(client resty.Client, baseUrl string, pat string) *SelfToken {
	u, err := url.Parse(baseUrl)
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to parse base URL")
	}
	u.Path = path.Join(u.Path, "api/v4/personal_access_tokens/self")
	currentToken := &SelfToken{}
	res, err := client.R().
		SetHeader("PRIVATE-TOKEN", pat).
		SetResult(currentToken).
		Get(u.String())

	if err != nil {
		log.Error().Err(err).Str("url", u.String()).Msg("Failed fetching token details (network or client error)")
		return nil
	}

	if res != nil && res.StatusCode() != 200 {
		log.Error().Int("status", res.StatusCode()).Str("url", u.String()).Str("response", res.String()).Msg("Failed fetching token details (HTTP error)")
		return nil
	}

	return currentToken
}

// https://docs.gitlab.com/api/personal_access_tokens/#list-all-token-associations
func fetchTokenAssociationsPage(client resty.Client, baseUrl string, pat string, accessLevel int, page int) (*TokenAssociations, int) {
	u, err := url.Parse(baseUrl)
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to parse base URL")
	}
	u.Path = path.Join(u.Path, "api/v4/personal_access_tokens/self/associations")
	resp := &TokenAssociations{}
	res, err := client.R().
		SetHeader("PRIVATE-TOKEN", pat).
		SetResult(resp).
		SetQueryParam("min_access_level", strconv.Itoa(accessLevel)).
		SetQueryParam("per_page", "100").
		SetQueryParam("page", strconv.Itoa(page)).
		Get(u.String())

	if err != nil {
		log.Error().Err(err).Str("url", u.String()).Msg("Failed fetching token associations (network or client error)")
		return nil, -1
	}
	if res != nil && res.StatusCode() != 200 {
		log.Error().Int("status", res.StatusCode()).Str("url", u.String()).Str("response", res.String()).Msg("Failed fetching token associations (HTTP error)")
		return nil, -1
	}

	nextPage, err := strconv.Atoi(res.Header().Get("x-next-page"))
	if err != nil {
		nextPage = -1
	}

	return resp, nextPage
}
