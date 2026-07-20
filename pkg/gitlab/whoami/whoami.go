package whoami

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/httpclient"
	"github.com/rs/zerolog/log"
)

// SelfUser represents the currently authenticated GitLab user.
type SelfUser struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	IsAdmin  bool   `json:"is_admin"`
	Bot      bool   `json:"bot"`
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

// Result contains the whoami response details.
type Result struct {
	User  *SelfUser
	Token *SelfToken
}

// RunWhoAmI fetches and prints current user and current token details.
func RunWhoAmI(gitlabURL string, gitlabAPIToken string) {
	result, err := FetchWhoAmI(gitlabURL, gitlabAPIToken)
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("Failed fetching GitLab whoami details")
	}

	log.Warn().
		Str("username", result.User.Username).
		Str("name", result.User.Name).
		Str("email", result.User.Email).
		Bool("admin", result.User.IsAdmin).
		Bool("bot", result.User.Bot).
		Msg("Current user")
	log.Debug().Interface("full_user", result.User).Msg("Full user details")

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
			Str("expiresAt", result.Token.ExpiresAt).
			Str("lastUsedIps", strings.Join(result.Token.LastUsedIps, ",")).
			Msg("Current token")
		log.Debug().Interface("full_token", result.Token).Msg("Full token details")
	}
}

// FetchWhoAmI retrieves the current GitLab user and token details.
func FetchWhoAmI(gitlabURL string, gitlabAPIToken string) (*Result, error) {
	user, err := fetchCurrentUser(gitlabURL, gitlabAPIToken)
	if err != nil {
		return nil, err
	}

	token, err := fetchCurrentToken(gitlabURL, gitlabAPIToken)
	if err != nil {
		return nil, err
	}

	return &Result{User: user, Token: token}, nil
}

func fetchCurrentUser(baseURL string, pat string) (*SelfUser, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	u.Path = path.Join(u.Path, "api/v4/user")

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
		return nil, fmt.Errorf("failed fetching current user: status=%d body=%s", res.StatusCode, string(bodyBytes))
	}

	currentUser := &SelfUser{}
	if err := json.Unmarshal(bodyBytes, currentUser); err != nil {
		return nil, err
	}

	return currentUser, nil
}

func fetchCurrentToken(baseURL string, pat string) (*SelfToken, error) {
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
