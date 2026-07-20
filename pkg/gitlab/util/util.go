package util

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/httpclient"
	"github.com/PuerkitoBio/goquery"
	"github.com/headzoo/surf"
	"github.com/rs/zerolog/log"
	gitlab "gitlab.com/gitlab-org/api/client-go"
	"resty.dev/v3"
)

// AccessLevelName returns the human-readable name for a GitLab access level value.
func AccessLevelName(level gitlab.AccessLevelValue) string {
	switch level {
	case gitlab.NoPermissions:
		return "No access"
	case gitlab.MinimalAccessPermissions:
		return "Minimal access"
	case gitlab.GuestPermissions:
		return "Guest"
	case gitlab.PlannerPermissions:
		return "Planner"
	case gitlab.ReporterPermissions:
		return "Reporter"
	case gitlab.AccessLevelValue(25):
		return "Security Manager"
	case gitlab.DeveloperPermissions:
		return "Developer"
	case gitlab.MaintainerPermissions:
		return "Maintainer"
	case gitlab.OwnerPermissions:
		return "Owner"
	case gitlab.AdminPermissions:
		return "Admin"
	default:
		return fmt.Sprintf("Unknown (%d)", int(level))
	}
}

// ParseAccessLevel converts a user-facing access level string into a GitLab access level value.
// It accepts documented names such as "developer" or "security-manager" and also numeric values.
func ParseAccessLevel(value string) (gitlab.AccessLevelValue, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.NewReplacer("_", " ", "-", " ").Replace(normalized)
	normalized = strings.Join(strings.Fields(normalized), " ")

	switch normalized {
	case "no access", "none":
		return gitlab.NoPermissions, nil
	case "minimal access", "minimal":
		return gitlab.MinimalAccessPermissions, nil
	case "guest":
		return gitlab.GuestPermissions, nil
	case "planner":
		return gitlab.PlannerPermissions, nil
	case "reporter":
		return gitlab.ReporterPermissions, nil
	case "security manager", "security":
		return gitlab.AccessLevelValue(25), nil
	case "developer":
		return gitlab.DeveloperPermissions, nil
	case "maintainer":
		return gitlab.MaintainerPermissions, nil
	case "owner":
		return gitlab.OwnerPermissions, nil
	case "admin":
		return gitlab.AdminPermissions, nil
	}

	if n, err := strconv.Atoi(normalized); err == nil {
		return gitlab.AccessLevelValue(n), nil
	}

	return 0, fmt.Errorf("invalid access level %q", value)
}

// AccessLevelHelpText describes the supported named and numeric access levels.
func AccessLevelHelpText() string {
	return "Minimum repo access level. Default is developer (30). Leave empty to disable filtering and return all associations. Accepted names: no access (0), minimal (5), guest (10), planner (15), reporter (20), security manager (25), developer (30), maintainer (40), owner (50), admin (60). Numeric values are also accepted."
}

// ProjectIteratorFunc is a callback function type for processing each project
type ProjectIteratorFunc func(project *gitlab.Project) error

// IterateProjects loops through projects with pagination and calls the provided
// callback function for each project. Returns an error if project fetching fails.
func IterateProjects(client *gitlab.Client, opts *gitlab.ListProjectsOptions, callback ProjectIteratorFunc) error {
	for {
		projects, resp, err := client.Projects.ListProjects(opts)
		if err != nil {
			log.Error().Stack().Err(err).Msg("Failed fetching projects")
			return err
		}

		for _, project := range projects {
			if err := callback(project); err != nil {
				return err
			}
		}

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return nil
}

// IterateGroupProjects loops through group projects with pagination and calls the provided
// callback function for each project. Returns an error if project fetching fails.
func IterateGroupProjects(client *gitlab.Client, groupID interface{}, opts *gitlab.ListGroupProjectsOptions, callback ProjectIteratorFunc) error {
	for {
		projects, resp, err := client.Groups.ListGroupProjects(groupID, opts)
		if err != nil {
			log.Error().Stack().Err(err).Msg("Failed fetching group projects")
			return err
		}

		for _, project := range projects {
			if err := callback(project); err != nil {
				return err
			}
		}

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return nil
}

func GetGitlabClient(token string, url string) (*gitlab.Client, error) {
	return gitlab.NewClient(token, gitlab.WithBaseURL(url), gitlab.WithHTTPClient(httpclient.GetPipeleekStandardHTTPClient()))
}

// SelfToken represents the current personal access token details returned by GitLab.
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

// FetchCurrentToken retrieves the current personal access token details from GitLab.
func FetchCurrentToken(baseURL string, pat string) (*SelfToken, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	u.Path = path.Join(u.Path, "api/v4/personal_access_tokens/self")

	httpClient := httpclient.GetPipeleekStandardHTTPClient()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("PRIVATE-TOKEN", pat)

	res, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed fetching current token: status=%d body=%s", res.StatusCode, string(bodyBytes))
	}

	currentToken := &SelfToken{}
	if err := json.Unmarshal(bodyBytes, currentToken); err != nil {
		return nil, err
	}

	return currentToken, nil
}

func CookieSessionValid(gitlabUrl string, cookieVal string) {
	gitlabSessionsUrl, _ := url.JoinPath(gitlabUrl, "-/user_settings/active_sessions")

	// #nosec G124 - Cookie attributes (Secure/HttpOnly/SameSite) are server-side browser directives; not applicable for client HTTP requests
	client := httpclient.GetPipeleekHTTPClient(gitlabUrl, []*http.Cookie{{Name: "_gitlab_session", Value: cookieVal}}, nil)
	resp, err := client.R().Get(gitlabSessionsUrl)
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Failed GitLab session test")
	}

	statCode := resp.StatusCode()

	if statCode != 200 {
		log.Fatal().Int("http", statCode).Str("testUrl", gitlabSessionsUrl).Msg("Invalid _gitlab_session, not auhthorized to access user sessions page for session validation")
	} else {
		log.Info().Msg("Provided GitLab session cookie is valid")
	}
}

func DetermineVersion(gitlabUrl string, apiToken string) *gitlab.Metadata {
	if len(apiToken) > 0 {
		git, err := GetGitlabClient(apiToken, gitlabUrl)
		if err != nil {
			return &gitlab.Metadata{Version: "none", Revision: "none", Enterprise: false}
		}

		metadata, _, err := git.Metadata.GetMetadata()
		if err != nil {
			log.Error().Stack().Err(err).Msg("Failed determining GitLab version via API")
			return &gitlab.Metadata{Version: "none", Revision: "none", Enterprise: false}
		}
		return metadata
	}

	return fetchVersionFromHTML(gitlabUrl, httpclient.GetPipeleekHTTPClient("", nil, nil))
}

// fetchVersionFromHTML fetches the GitLab version by scraping the /help page HTML.
// Accepts a Resty client to allow injection for testing.
func fetchVersionFromHTML(gitlabUrl string, client *resty.Client) *gitlab.Metadata {
	u, err := url.Parse(gitlabUrl)
	if err != nil {
		log.Error().Stack().Err(err).Msg("Failed determining GitLab version via Website")
		return &gitlab.Metadata{Version: "none", Revision: "none", Enterprise: false}
	}
	u.Path = path.Join(u.Path, "/help")

	response, err := client.R().Get(u.String())

	if err != nil {
		log.Error().Stack().Err(err).Msg("Failed determining GitLab version via Website")
		return &gitlab.Metadata{Version: "none", Revision: "none", Enterprise: false}
	}

	responseData := response.Bytes()

	extractLineR := regexp.MustCompile(`instance_version":"\d*.\d*.\d*"`)
	fullLine := extractLineR.Find(responseData)
	versionR := regexp.MustCompile(`\d+.\d+.\d+`)
	versionNumber := versionR.Find(fullLine)

	if len(versionNumber) > 3 {
		return &gitlab.Metadata{Version: string(versionNumber), Revision: "none", Enterprise: false}
	}

	log.Error().Msg("Failed determining GitLab version via Website")
	return &gitlab.Metadata{Version: "none", Revision: "none", Enterprise: false}
}

func RegisterNewAccount(targetUrl string, username string, password string, email string) {

	log.Info().Msg("Best effort registration automation - not very reliable")

	gitlabUrl, err := url.Parse(targetUrl)
	if err != nil {
		log.Fatal().Msg(err.Error())
	}

	gitlabUrl.Path = "/users/sign_up"

	log.Debug().Msg("Navigate to login page")
	bow := surf.NewBrowser()
	err = bow.Open(gitlabUrl.String())
	if err != nil {
		log.Fatal().Msg(err.Error())
	}

	log.Debug().Msg("Submit registration form")
	fm, err := bow.Form("#new_new_user")

	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Failed parsing sign-up form")
	}

	_ = fm.Input("new_user[name]", "Pipeleek Full Name")
	_ = fm.Input("new_user[first_name]", "Pipeleek First Name")
	_ = fm.Input("new_user[last_name]", "Automated Signup")
	_ = fm.Input("new_user[username]", username)
	_ = fm.Input("new_user[email]", email)
	_ = fm.Input("new_user[email_confirmation]", email)
	_ = fm.Input("new_user[password]", password)

	if fm.Submit() != nil {
		log.Error().Msg("Registration failed 🙀 do it manually or try with the -v flag")
		log.Fatal().Msg(err.Error())
	}

	bow.Dom().Find(".navless-container").Each(func(_ int, s *goquery.Selection) {
		log.Debug().Msg(strings.ReplaceAll(s.Text(), "\n\n", ""))
	})

	hasErrors := false
	bow.Dom().Find("#error_explanation").Each(func(_ int, s *goquery.Selection) {
		log.Error().Msg(strings.ReplaceAll(s.Text(), "\n\n", ""))
		hasErrors = true
	})

	bow.Dom().Find(".gl-alert-content").Each(func(_ int, s *goquery.Selection) {
		log.Error().Msg(strings.ReplaceAll(s.Text(), "\n\n", ""))
		hasErrors = true
	})

	if hasErrors {
		log.Error().Msg("Failed registration. Check output above or try with -v")
	} else {
		gitlabUrl.Path = "/users/sign_in"
		log.Info().Str("url", gitlabUrl.String()).Msg("Done! Check your inbox to confirm the account if needed or login directly")
	}
}

func FetchCICDYml(git *gitlab.Client, pid int64) (string, error) {
	lintOpts := &gitlab.ProjectLintOptions{
		IncludeJobs: gitlab.Ptr(true),
	}
	res, _, err := git.Validate.ProjectLint(int(pid), lintOpts)

	if err != nil {
		return "", err
	}

	for _, msg := range res.Errors {
		log.Debug().Str("type", msg).Msg("Validation error of gitlab-ci.yml in project")

		// API does not distinguish between missing file and actual errors in the YAML
		if strings.Contains(msg, "Please provide content of") {
			return "", errors.New("project does most certainly not have a .gitlab-ci.yml file")
		}
	}

	if len(res.Errors) > 0 {
		return "", errors.New(strings.Join(res.Errors, ", "))
	}

	log.Trace().Bool("valid", res.Valid).Str("warnings", strings.Join(res.Warnings, ", ")).Msg(".gitlab-ci.yaml")

	return res.MergedYaml, nil
}
