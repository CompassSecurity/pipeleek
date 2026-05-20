package scan

import (
	"testing"

	"github.com/CompassSecurity/pipeleek/pkg/config"
	pkggithub "github.com/CompassSecurity/pipeleek/pkg/github/scan"
)

func TestNewScanCmd(t *testing.T) {
	cmd := NewScanCmd()

	if cmd == nil {
		t.Fatal("Expected non-nil command")
		return
	}

	if cmd.Use != "scan [no options!]" {
		t.Errorf("Expected Use to be 'scan [no options!]', got %q", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("Expected non-empty Short description")
	}

	if cmd.Example == "" {
		t.Error("Expected non-empty Example")
	}

	flags := cmd.Flags()

	if flags.Lookup("token") == nil {
		t.Error("Expected 'token' flag to exist")
	}
	if flags.Lookup("confidence") == nil {
		t.Error("Expected 'confidence' flag to exist")
	}
	if flags.Lookup("threads") == nil {
		t.Error("Expected 'threads' flag to exist")
	}
	if flags.Lookup("truffle-hog-verification") == nil {
		t.Error("Expected 'truffle-hog-verification' flag to exist")
	}
	if flags.Lookup("max-workflows") == nil {
		t.Error("Expected 'max-workflows' flag to exist")
	}
	if flags.Lookup("artifacts") == nil {
		t.Error("Expected 'artifacts' flag to exist")
	}
	if flags.Lookup("org") == nil {
		t.Error("Expected 'org' flag to exist")
	}
	if flags.Lookup("user") == nil {
		t.Error("Expected 'user' flag to exist")
	}
	if flags.Lookup("owned") == nil {
		t.Error("Expected 'owned' flag to exist")
	}
	if flags.Lookup("public") == nil {
		t.Error("Expected 'public' flag to exist")
	}
	if flags.Lookup("search") == nil {
		t.Error("Expected 'search' flag to exist")
	}
	if flags.Lookup("repo") == nil {
		t.Error("Expected 'repo' flag to exist")
	}
}

func TestGitHubScanCmd_PersistentFlags(t *testing.T) {
	// Note: 'url' and 'token' are persistent flags on the parent github command,
	// not on the scan subcommand itself, so they're not in cmd.Flags()
}

func TestGitHubScanOptions(t *testing.T) {
	opts := GitHubScanOptions{
		CommonScanOptions: config.CommonScanOptions{
			ConfidenceFilter:       []string{"high", "verified"},
			MaxScanGoRoutines:      8,
			TruffleHogVerification: true,
			Artifacts:              true,
			Owned:                  false,
		},
		AccessToken:  "ghp_test123",
		MaxWorkflows: 20,
		Organization: "apache",
		User:         "testuser",
		Public:       true,
		SearchQuery:  "security",
		GitHubURL:    "https://api.github.com",
	}

	if opts.AccessToken != "ghp_test123" {
		t.Errorf("Expected AccessToken 'ghp_test123', got %q", opts.AccessToken)
	}
	if len(opts.ConfidenceFilter) != 2 {
		t.Errorf("Expected 2 confidence filters, got %d", len(opts.ConfidenceFilter))
	}
	if opts.MaxScanGoRoutines != 8 {
		t.Errorf("Expected MaxScanGoRoutines 8, got %d", opts.MaxScanGoRoutines)
	}
	if !opts.TruffleHogVerification {
		t.Error("Expected TruffleHogVerification to be true")
	}
	if opts.MaxWorkflows != 20 {
		t.Errorf("Expected MaxWorkflows 20, got %d", opts.MaxWorkflows)
	}
	if opts.Organization != "apache" {
		t.Errorf("Expected Organization 'apache', got %q", opts.Organization)
	}
	if opts.Owned {
		t.Error("Expected Owned to be false")
	}
	if opts.User != "testuser" {
		t.Errorf("Expected User 'testuser', got %q", opts.User)
	}
	if !opts.Public {
		t.Error("Expected Public to be true")
	}
	if opts.SearchQuery != "security" {
		t.Errorf("Expected SearchQuery 'security', got %q", opts.SearchQuery)
	}
	if !opts.Artifacts {
		t.Error("Expected Artifacts to be true")
	}
	if opts.GitHubURL != "https://api.github.com" {
		t.Errorf("Expected GitHubURL 'https://api.github.com', got %q", opts.GitHubURL)
	}
}

func TestValidateRepoFormat(t *testing.T) {
	tests := []struct {
		name      string
		repo      string
		wantOwner string
		wantName  string
		wantValid bool
	}{
		{
			name:      "valid repo format",
			repo:      "owner/repo",
			wantOwner: "owner",
			wantName:  "repo",
			wantValid: true,
		},
		{
			name:      "valid repo with hyphen",
			repo:      "my-org/my-repo",
			wantOwner: "my-org",
			wantName:  "my-repo",
			wantValid: true,
		},
		{
			name:      "valid repo with underscore",
			repo:      "my_org/my_repo",
			wantOwner: "my_org",
			wantName:  "my_repo",
			wantValid: true,
		},
		{
			name:      "invalid - missing owner",
			repo:      "/repo",
			wantOwner: "",
			wantName:  "",
			wantValid: false,
		},
		{
			name:      "invalid - missing repo",
			repo:      "owner/",
			wantOwner: "",
			wantName:  "",
			wantValid: false,
		},
		{
			name:      "invalid - no slash",
			repo:      "ownerrepo",
			wantOwner: "",
			wantName:  "",
			wantValid: false,
		},
		{
			name:      "invalid - multiple slashes",
			repo:      "owner/repo/extra",
			wantOwner: "",
			wantName:  "",
			wantValid: false,
		},
		{
			name:      "invalid - empty string",
			repo:      "",
			wantOwner: "",
			wantName:  "",
			wantValid: false,
		},
		{
			name:      "invalid - only slash",
			repo:      "/",
			wantOwner: "",
			wantName:  "",
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOwner, gotName, gotValid := pkggithub.ValidateRepoFormat(tt.repo)
			if gotOwner != tt.wantOwner {
				t.Errorf("pkggithub.ValidateRepoFormat() gotOwner = %v, want %v", gotOwner, tt.wantOwner)
			}
			if gotName != tt.wantName {
				t.Errorf("pkggithub.ValidateRepoFormat() gotName = %v, want %v", gotName, tt.wantName)
			}
			if gotValid != tt.wantValid {
				t.Errorf("pkggithub.ValidateRepoFormat() gotValid = %v, want %v", gotValid, tt.wantValid)
			}
		})
	}
}
