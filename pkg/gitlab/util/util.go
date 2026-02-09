package util

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/CompassSecurity/pipeleek/pkg/httpclient"
	"github.com/PuerkitoBio/goquery"
	"github.com/headzoo/surf"
	"github.com/rs/zerolog/log"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

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

		if resp.NextPage == 0 || resp.NextPage == opts.Page {
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

		if resp.NextPage == 0 || resp.NextPage == opts.Page {
			break
		}
		opts.Page = resp.NextPage
	}

	return nil
}

func GetGitlabClient(token string, url string) (*gitlab.Client, error) {
	return gitlab.NewClient(token, gitlab.WithBaseURL(url), gitlab.WithHTTPClient(httpclient.GetPipeleekHTTPClient("", nil, nil).StandardClient()))
}

func GetGitlabJobClient(token string, url string) (*gitlab.Client, error) {
	return gitlab.NewJobClient(token, gitlab.WithBaseURL(url), gitlab.WithHTTPClient(httpclient.GetPipeleekHTTPClient("", nil, nil).StandardClient()))
}

func CookieSessionValid(gitlabUrl string, cookieVal string) {
	gitlabSessionsUrl, _ := url.JoinPath(gitlabUrl, "-/user_settings/active_sessions")

	client := httpclient.GetPipeleekHTTPClient(gitlabUrl, []*http.Cookie{{Name: "_gitlab_session", Value: cookieVal}}, nil)
	resp, err := client.Get(gitlabSessionsUrl)
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Failed GitLab session test")
	}
	defer func() { _ = resp.Body.Close() }()

	statCode := resp.StatusCode

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
	} else {
		u, err := url.Parse(gitlabUrl)
		if err != nil {
			log.Error().Stack().Err(err).Msg("Failed determining GitLab version via Website")
			return &gitlab.Metadata{Version: "none", Revision: "none", Enterprise: false}
		}
		u.Path = path.Join(u.Path, "/help")

		client := httpclient.GetPipeleekHTTPClient("", nil, nil)
		response, err := client.Get(u.String())

		if err != nil {
			log.Error().Stack().Err(err).Msg("Failed determining GitLab version via Website")
			return &gitlab.Metadata{Version: "none", Revision: "none", Enterprise: false}
		}

		responseData, err := io.ReadAll(response.Body)
		if err != nil {
			log.Error().Stack().Err(err).Msg("Failed determining GitLab version via Website")
			return &gitlab.Metadata{Version: "none", Revision: "none", Enterprise: false}
		}

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
