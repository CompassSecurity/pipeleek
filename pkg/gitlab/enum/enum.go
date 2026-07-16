package enum

import (
	"errors"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	gitlabutil "github.com/CompassSecurity/pipeleek/pkg/gitlab/util"
	"github.com/CompassSecurity/pipeleek/pkg/httpclient"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	gitlab "gitlab.com/gitlab-org/api/client-go"

	"resty.dev/v3"
)

// ExportOptions controls optional enum artifact generation.
type ExportOptions struct {
	HTMLReportPath string
	EnumerateUsers bool
	UsersConcurrency int
}

// EnumResult contains collected user, token and access association data.
type EnumResult struct {
	GeneratedAt     time.Time          `json:"generated_at"`
	GitLabURL       string             `json:"gitlab_url"`
	MinAccessLevel  int                `json:"min_access_level"`
	MinAccessFilterApplied bool        `json:"min_access_filter_applied"`
	UsersEnumerated bool               `json:"users_enumerated"`
	User            *gitlab.User       `json:"user"`
	Users           []*gitlab.User     `json:"users"`
	Token           *SelfToken         `json:"token"`
	Associations    *TokenAssociations `json:"associations"`
}

type enumStatusTracker struct {
	mu                sync.RWMutex
	startedAt         time.Time
	stage             string
	usersEnabled      bool
	associationPages  int
	groupsDiscovered  int
	projectsDiscovered int
	groupTargets      int
	projectTargets    int
	groupsProcessed   int
	projectsProcessed int
	usersCollected    int
}

var statusTracker = &enumStatusTracker{}

const usersFetchWorkerCount = 2

type scopedMemberFetchKind string

const (
	scopedMemberFetchGroup   scopedMemberFetchKind = "group"
	scopedMemberFetchProject scopedMemberFetchKind = "project"
)

type scopedMemberFetchJob struct {
	kind           scopedMemberFetchKind
	id             int
	label          string
	groupIndexes   []int
	projectIndexes []int
}

type scopedMemberFetchResult struct {
	job        scopedMemberFetchJob
	members    []TokenAssociationMember
	accessible bool
	err        error
}

// StatusHook returns the current enum progress for the status key shortcut.
func StatusHook() *zerolog.Event {
	return statusTracker.event()
}

func (s *enumStatusTracker) reset(usersEnabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.startedAt = time.Now()
	s.stage = "starting"
	s.usersEnabled = usersEnabled
	s.associationPages = 0
	s.groupsDiscovered = 0
	s.projectsDiscovered = 0
	s.groupTargets = 0
	s.projectTargets = 0
	s.groupsProcessed = 0
	s.projectsProcessed = 0
	s.usersCollected = 0
}

func (s *enumStatusTracker) setStage(stage string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stage = stage
}

func (s *enumStatusTracker) addAssociationPage(groups int, projects int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.associationPages++
	s.groupsDiscovered += groups
	s.projectsDiscovered += projects
}

func (s *enumStatusTracker) markGroupProcessed() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.groupsProcessed++
}

func (s *enumStatusTracker) markProjectProcessed() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.projectsProcessed++
}

func (s *enumStatusTracker) setUsersCollected(users int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.usersCollected = users
}

func (s *enumStatusTracker) setProcessingTargets(groups int, projects int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.groupTargets = groups
	s.projectTargets = projects
	s.groupsProcessed = 0
	s.projectsProcessed = 0
}

func (s *enumStatusTracker) event() *zerolog.Event {
	s.mu.RLock()
	defer s.mu.RUnlock()

	progressCurrent, progressTotal, progressPercent, progressKnown := s.progressSnapshot()

	event := log.Info().
		Str("stage", s.stage).
		Bool("usersEnabled", s.usersEnabled).
		Bool("progressKnown", progressKnown).
		Int("progressCurrent", progressCurrent).
		Int("progressTotal", progressTotal).
		Int("progressPercent", progressPercent).
		Int("associationPages", s.associationPages).
		Int("groupsDiscovered", s.groupsDiscovered).
		Int("projectsDiscovered", s.projectsDiscovered).
		Int("groupsProcessed", s.groupsProcessed).
		Int("projectsProcessed", s.projectsProcessed).
		Int("usersCollected", s.usersCollected)

	if !s.startedAt.IsZero() {
		event = event.Dur("elapsed", time.Since(s.startedAt))
	}

	return event
}

func (s *enumStatusTracker) progressSnapshot() (current int, total int, percent int, known bool) {
	if s.stage == "completed" {
		return 1, 1, 100, true
	}

	if s.stage != "collecting_users" {
		return s.associationPages, 0, -1, false
	}

	totalGroups := s.groupsDiscovered
	totalProjects := s.projectsDiscovered
	if s.groupTargets > 0 || s.projectTargets > 0 {
		totalGroups = s.groupTargets
		totalProjects = s.projectTargets
	}

	total = totalGroups + totalProjects
	current = s.groupsProcessed + s.projectsProcessed
	if total <= 0 {
		return current, total, -1, false
	}

	percent = (current * 100) / total
	if percent > 100 {
		percent = 100
	}

	return current, total, percent, true
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
	statusTracker.reset(opts.EnumerateUsers)
	result := collectEnumData(gitlabUrl, gitlabApiToken, minAccessLevel, opts.EnumerateUsers, opts.UsersConcurrency)
	statusTracker.setUsersCollected(len(result.Users))
	statusTracker.setStage("completed")
	logEnumResult(result)

	if opts.HTMLReportPath != "" {
		if err := WriteHTMLReport(result, opts.HTMLReportPath); err != nil {
			log.Fatal().Stack().Err(err).Str("path", opts.HTMLReportPath).Msg("Failed writing enum HTML report")
		}
		log.Info().Str("path", opts.HTMLReportPath).Msg("Wrote enum HTML report")
	}

	log.Info().Msg("Done")
}

func collectEnumData(gitlabUrl, gitlabApiToken string, minAccessLevel int, enumerateUsers bool, usersConcurrency int) *EnumResult {
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
	useMinAccessFilter := minAccessLevel > 0
	appliedMinAccessLevel := minAccessLevel
	statusTracker.setStage("collecting_associations")
	log.Info().Msg("Collecting token associations")
	for page != -1 {
		log.Debug().Int("page", page).Msg("Requesting token association page")
		batch, nextPage, usedMinAccessFilter := fetchTokenAssociationsPage(client, gitlabUrl, gitlabApiToken, minAccessLevel, page, useMinAccessFilter)
		useMinAccessFilter = usedMinAccessFilter
		if !useMinAccessFilter {
			appliedMinAccessLevel = 0
		}
		if batch != nil {
			statusTracker.addAssociationPage(len(batch.Groups), len(batch.Projects))
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
		} else {
			log.Warn().
				Int("page", page).
				Msg("Token associations fetch failed. The API can be unstable; try rerunning with --level developer (or higher), which usually works best")
			log.Fatal().Int("page", page).Msg("Failed fetching token associations; aborting enum to avoid incomplete results")
		}
		page = nextPage
	}

	users := make([]*gitlab.User, 0)
	if enumerateUsers {
		startedAt := time.Now()
		statusTracker.setStage("collecting_users")
		log.Info().Msg("Collecting scoped members from discovered groups and projects")
		fetchedUsers, fetchErr := collectScopedUsersFromAssociations(git, associations, usersConcurrency)
		if fetchErr != nil {
			log.Warn().Err(fetchErr).Msg("Failed enumerating users from associated groups/projects; continuing without users section data")
		} else {
			users = fetchedUsers
		}
		log.Info().Dur("duration", time.Since(startedAt)).Int("users", len(users)).Int("groups", len(associations.Groups)).Int("projects", len(associations.Projects)).Msg("Finished scoped users enumeration")
	}

	return &EnumResult{
		GeneratedAt:     time.Now().UTC(),
		GitLabURL:       gitlabUrl,
		MinAccessLevel:  appliedMinAccessLevel,
		MinAccessFilterApplied: useMinAccessFilter,
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

func collectScopedUsersFromAssociations(git *gitlab.Client, associations *TokenAssociations, usersConcurrency int) ([]*gitlab.User, error) {
	usersByID := make(map[int64]*gitlab.User)
	usersByUsername := make(map[string]*gitlab.User)
	groupIndexesByID := make(map[int][]int)
	projectIndexesByID := make(map[int][]int)

	for i := range associations.Groups {
		groupIndexesByID[associations.Groups[i].ID] = append(groupIndexesByID[associations.Groups[i].ID], i)
	}

	for i := range associations.Projects {
		projectIndexesByID[associations.Projects[i].ID] = append(projectIndexesByID[associations.Projects[i].ID], i)
	}

	statusTracker.setProcessingTargets(len(groupIndexesByID), len(projectIndexesByID))

	jobs := make([]scopedMemberFetchJob, 0, len(groupIndexesByID)+len(projectIndexesByID))
	for groupID, indexes := range groupIndexesByID {
		representative := &associations.Groups[indexes[0]]
		jobs = append(jobs, scopedMemberFetchJob{
			kind:         scopedMemberFetchGroup,
			id:           groupID,
			label:        representative.Name,
			groupIndexes: indexes,
		})
		log.Info().Int("groupId", representative.ID).Str("group", representative.Name).Int("occurrences", len(indexes)).Msg("Queueing group members enumeration")
	}

	for projectID, indexes := range projectIndexesByID {
		representative := &associations.Projects[indexes[0]]
		jobs = append(jobs, scopedMemberFetchJob{
			kind:           scopedMemberFetchProject,
			id:             projectID,
			label:          representative.NameWithNamespace,
			projectIndexes: indexes,
		})
		log.Info().Int("projectId", representative.ID).Str("project", representative.NameWithNamespace).Int("occurrences", len(indexes)).Msg("Queueing project members enumeration")
	}

	if len(jobs) == 0 {
		return make([]*gitlab.User, 0), nil
	}

	workerCount := usersFetchWorkerCount
	if usersConcurrency > 0 {
		workerCount = usersConcurrency
	}
	if len(jobs) < workerCount {
		workerCount = len(jobs)
	}

	jobCh := make(chan scopedMemberFetchJob)
	resultCh := make(chan scopedMemberFetchResult, len(jobs))

	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		for job := range jobCh {
			result := scopedMemberFetchResult{job: job}
			switch job.kind {
			case scopedMemberFetchGroup:
				result.members, result.accessible, result.err = fetchGroupMembers(git, int64(job.id))
			case scopedMemberFetchProject:
				result.members, result.accessible, result.err = fetchProjectMembers(git, int64(job.id))
			}
			resultCh <- result
		}
	}

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go worker()
	}

	go func() {
		for _, job := range jobs {
			jobCh <- job
		}
		close(jobCh)
		wg.Wait()
		close(resultCh)
	}()

	for result := range resultCh {
		switch result.job.kind {
		case scopedMemberFetchGroup:
			statusTracker.markGroupProcessed()
			for _, idx := range result.job.groupIndexes {
				group := &associations.Groups[idx]
				group.MembersEnumerated = true
				group.MembersAccessible = result.accessible
				if result.err != nil {
					group.MembersError = result.err.Error()
					continue
				}
				group.Members = result.members
				group.MemberCount = len(result.members)
			}
			if result.err != nil {
				log.Warn().Err(result.err).Int("groupId", result.job.id).Str("group", result.job.label).Msg("Failed enumerating group members")
				continue
			}
			log.Info().Int("groupId", result.job.id).Str("group", result.job.label).Int("members", len(result.members)).Msg("Enumerated group members")
		case scopedMemberFetchProject:
			statusTracker.markProjectProcessed()
			for _, idx := range result.job.projectIndexes {
				project := &associations.Projects[idx]
				project.MembersEnumerated = true
				project.MembersAccessible = result.accessible
				if result.err != nil {
					project.MembersError = result.err.Error()
					continue
				}
				project.Members = result.members
				project.MemberCount = len(result.members)
			}
			if result.err != nil {
				log.Warn().Err(result.err).Int("projectId", result.job.id).Str("project", result.job.label).Msg("Failed enumerating project members")
				continue
			}
			log.Info().Int("projectId", result.job.id).Str("project", result.job.label).Int("members", len(result.members)).Msg("Enumerated project members")
		}

		for _, member := range result.members {
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
func fetchTokenAssociationsPage(client resty.Client, baseUrl string, pat string, accessLevel int, page int, includeMinAccessFilter bool) (*TokenAssociations, int, bool) {
	u, err := url.Parse(baseUrl)
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to parse base URL")
	}
	u.Path = path.Join(u.Path, "api/v4/personal_access_tokens/self/associations")

	if includeMinAccessFilter && accessLevel <= 0 {
		log.Warn().
			Int("requestedMinAccessLevel", accessLevel).
			Str("url", u.String()).
			Msg("GitLab token associations endpoint does not support non-positive min_access_level values; querying without min_access_level filter")
		includeMinAccessFilter = false
	}

	if includeMinAccessFilter && accessLevel == int(gitlab.MinimalAccessPermissions) {
		log.Warn().
			Int("requestedMinAccessLevel", accessLevel).
			Str("url", u.String()).
			Msg("GitLab token associations endpoint does not support min_access_level=minimal (5); querying without min_access_level filter")
		includeMinAccessFilter = false
	}

	resp, res, err := requestTokenAssociationsPage(client, u.String(), pat, accessLevel, page, includeMinAccessFilter)
	if err != nil {
		log.Error().Err(err).Str("url", u.String()).Msg("Failed fetching token associations (network or client error)")
		return nil, -1, includeMinAccessFilter
	}

	if res == nil {
		log.Error().Str("url", u.String()).Msg("Failed fetching token associations (empty HTTP response)")
		return nil, -1, includeMinAccessFilter
	}

	if res.StatusCode() == 200 {
		nextPage, parseErr := strconv.Atoi(res.Header().Get("x-next-page"))
		if parseErr != nil {
			nextPage = -1
		}
		return resp, nextPage, includeMinAccessFilter
	}

	if includeMinAccessFilter && hasInvalidMinAccessLevelError(res) {
		log.Warn().
			Int("requestedMinAccessLevel", accessLevel).
			Str("url", u.String()).
			Msg("GitLab API rejected min_access_level; retrying token associations without min_access_level filter")

		resp, res, err = requestTokenAssociationsPage(client, u.String(), pat, accessLevel, page, false)
		if err != nil {
			log.Error().Err(err).Str("url", u.String()).Msg("Failed fetching token associations fallback request (network or client error)")
			return nil, -1, false
		}
		if res == nil || res.StatusCode() != 200 {
			status := 0
			body := ""
			if res != nil {
				status = res.StatusCode()
				body = res.String()
			}
			log.Error().Int("status", status).Str("url", u.String()).Str("response", body).Msg("Failed fetching token associations fallback request (HTTP error)")
			return nil, -1, false
		}

		nextPage, parseErr := strconv.Atoi(res.Header().Get("x-next-page"))
		if parseErr != nil {
			nextPage = -1
		}
		return resp, nextPage, false
	}

	log.Error().Int("status", res.StatusCode()).Str("url", u.String()).Str("response", res.String()).Msg("Failed fetching token associations (HTTP error)")
	return nil, -1, includeMinAccessFilter
}

func requestTokenAssociationsPage(client resty.Client, endpointURL string, pat string, accessLevel int, page int, includeMinAccessFilter bool) (*TokenAssociations, *resty.Response, error) {
	resp := &TokenAssociations{}
	req := client.R().
		SetHeader("PRIVATE-TOKEN", pat).
		SetResult(resp).
		SetQueryParam("per_page", "100").
		SetQueryParam("page", strconv.Itoa(page))

	if includeMinAccessFilter {
		req.SetQueryParam("min_access_level", strconv.Itoa(accessLevel))
	}

	res, err := req.Get(endpointURL)
	return resp, res, err
}

func hasInvalidMinAccessLevelError(res *resty.Response) bool {
	if res == nil {
		return false
	}
	if res.StatusCode() != 400 {
		return false
	}
	bodyLower := strings.ToLower(res.String())
	return strings.Contains(bodyLower, "min_access_level") && strings.Contains(bodyLower, "valid value")
}
