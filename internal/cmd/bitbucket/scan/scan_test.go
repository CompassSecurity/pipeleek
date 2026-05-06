package scan

import (
	"testing"

	"github.com/CompassSecurity/pipeleek/pkg/config"
)

func TestNewScanCmd(t *testing.T) {
	cmd := NewScanCmd()

	if cmd == nil {
		t.Fatal("Expected non-nil command")
		return
	}

	if cmd.Use != "scan" {
		t.Errorf("Expected Use to be 'scan', got %q", cmd.Use)
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
	if flags.Lookup("email") == nil {
		t.Error("Expected 'email' flag to exist")
	}
	if flags.Lookup("cookie") == nil {
		t.Error("Expected 'cookie' flag to exist")
	}
	if flags.Lookup("bitbucket") == nil {
		t.Error("Expected 'bitbucket' flag to exist")
	}
	if flags.Lookup("artifacts") == nil {
		t.Error("Expected 'artifacts' flag to exist")
	}
	if flags.Lookup("workspace") == nil {
		t.Error("Expected 'workspace' flag to exist")
	}
	if flags.Lookup("owned") == nil {
		t.Error("Expected 'owned' flag to exist")
	}
	if flags.Lookup("public") == nil {
		t.Error("Expected 'public' flag to exist")
	}
	if flags.Lookup("after") == nil {
		t.Error("Expected 'after' flag to exist")
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
	if flags.Lookup("max-pipelines") == nil {
		t.Error("Expected 'max-pipelines' flag to exist")
	}
	if flags.Lookup("max-artifact-size") == nil {
		t.Error("Expected 'max-artifact-size' flag to exist")
	}
}

func TestBitBucketScanFlagBindings(t *testing.T) {
	t.Setenv("PIPELEEK_NO_CONFIG", "1")

	if err := config.InitializeViper(""); err != nil {
		t.Fatalf("InitializeViper failed: %v", err)
	}

	cmd := NewScanCmd()

	if err := cmd.Flags().Set("workspace", "my-workspace"); err != nil {
		t.Fatalf("Failed to set workspace flag: %v", err)
	}
	if err := cmd.Flags().Set("public", "true"); err != nil {
		t.Fatalf("Failed to set public flag: %v", err)
	}
	if err := cmd.Flags().Set("artifacts", "true"); err != nil {
		t.Fatalf("Failed to set artifacts flag: %v", err)
	}
	if err := cmd.Flags().Set("owned", "true"); err != nil {
		t.Fatalf("Failed to set owned flag: %v", err)
	}
	if err := cmd.Flags().Set("after", "2025-01-01T00:00:00Z"); err != nil {
		t.Fatalf("Failed to set after flag: %v", err)
	}

	if err := config.AutoBindFlags(cmd, map[string]string{
		"bitbucket":                "bitbucket.url",
		"token":                    "bitbucket.token",
		"email":                    "bitbucket.email",
		"cookie":                   "bitbucket.cookie",
		"workspace":                "bitbucket.scan.workspace",
		"max-pipelines":            "bitbucket.scan.max_pipelines",
		"public":                   "bitbucket.scan.public",
		"after":                    "bitbucket.scan.after",
		"artifacts":                "bitbucket.scan.artifacts",
		"owned":                    "bitbucket.scan.owned",
		"threads":                  "common.threads",
		"truffle-hog-verification": "common.trufflehog_verification",
		"max-artifact-size":        "common.max_artifact_size",
		"confidence":               "common.confidence_filter",
		"hit-timeout":              "common.hit_timeout",
	}); err != nil {
		t.Fatalf("AutoBindFlags failed: %v", err)
	}

	if got := config.GetString("bitbucket.scan.workspace"); got != "my-workspace" {
		t.Errorf("Expected bitbucket.scan.workspace=%q, got %q", "my-workspace", got)
	}
	if got := config.GetBool("bitbucket.scan.public"); !got {
		t.Error("Expected bitbucket.scan.public=true")
	}
	if got := config.GetBool("bitbucket.scan.artifacts"); !got {
		t.Error("Expected bitbucket.scan.artifacts=true")
	}
	if got := config.GetBool("bitbucket.scan.owned"); !got {
		t.Error("Expected bitbucket.scan.owned=true")
	}
	if got := config.GetString("bitbucket.scan.after"); got != "2025-01-01T00:00:00Z" {
		t.Errorf("Expected bitbucket.scan.after=%q, got %q", "2025-01-01T00:00:00Z", got)
	}
}

func TestBitBucketScanEnvVarBinding(t *testing.T) {
	t.Setenv("PIPELEEK_NO_CONFIG", "1")
	t.Setenv("PIPELEEK_BITBUCKET_SCAN_WORKSPACE", "env-workspace")
	t.Setenv("PIPELEEK_BITBUCKET_SCAN_PUBLIC", "true")

	if err := config.InitializeViper(""); err != nil {
		t.Fatalf("InitializeViper failed: %v", err)
	}

	cmd := NewScanCmd()

	if err := config.AutoBindFlags(cmd, map[string]string{
		"workspace": "bitbucket.scan.workspace",
		"public":    "bitbucket.scan.public",
	}); err != nil {
		t.Fatalf("AutoBindFlags failed: %v", err)
	}

	if got := config.GetString("bitbucket.scan.workspace"); got != "env-workspace" {
		t.Errorf("Expected bitbucket.scan.workspace=%q from env var, got %q", "env-workspace", got)
	}
	if got := config.GetBool("bitbucket.scan.public"); !got {
		t.Errorf("Expected bitbucket.scan.public=true from env var, got %v", got)
	}
}

func TestBitBucketScanOptions(t *testing.T) {
	opts := BitBucketScanOptions{
		CommonScanOptions: config.CommonScanOptions{
			ConfidenceFilter:       []string{"high", "medium"},
			MaxScanGoRoutines:      4,
			TruffleHogVerification: true,
			Artifacts:              true,
			Owned:                  true,
		},
		Email:           "test@example.com",
		AccessToken:     "token123",
		MaxPipelines:    10,
		Workspace:       "myworkspace",
		Public:          false,
		After:           "2025-01-01T00:00:00Z",
		BitBucketURL:    "https://api.bitbucket.org/2.0",
		BitBucketCookie: "cookie123",
	}

	if opts.Email != "test@example.com" {
		t.Errorf("Expected Email 'test@example.com', got %q", opts.Email)
	}
	if opts.AccessToken != "token123" {
		t.Errorf("Expected AccessToken 'token123', got %q", opts.AccessToken)
	}
	if len(opts.ConfidenceFilter) != 2 {
		t.Errorf("Expected 2 confidence filters, got %d", len(opts.ConfidenceFilter))
	}
	if opts.MaxScanGoRoutines != 4 {
		t.Errorf("Expected MaxScanGoRoutines 4, got %d", opts.MaxScanGoRoutines)
	}
	if !opts.TruffleHogVerification {
		t.Error("Expected TruffleHogVerification to be true")
	}
	if opts.MaxPipelines != 10 {
		t.Errorf("Expected MaxPipelines 10, got %d", opts.MaxPipelines)
	}
	if opts.Workspace != "myworkspace" {
		t.Errorf("Expected Workspace 'myworkspace', got %q", opts.Workspace)
	}
	if !opts.Owned {
		t.Error("Expected Owned to be true")
	}
	if opts.Public {
		t.Error("Expected Public to be false")
	}
	if opts.After != "2025-01-01T00:00:00Z" {
		t.Errorf("Expected After '2025-01-01T00:00:00Z', got %q", opts.After)
	}
	if !opts.Artifacts {
		t.Error("Expected Artifacts to be true")
	}
	if opts.BitBucketURL != "https://api.bitbucket.org/2.0" {
		t.Errorf("Expected BitBucketURL 'https://api.bitbucket.org/2.0', got %q", opts.BitBucketURL)
	}
	if opts.BitBucketCookie != "cookie123" {
		t.Errorf("Expected BitBucketCookie 'cookie123', got %q", opts.BitBucketCookie)
	}
}
