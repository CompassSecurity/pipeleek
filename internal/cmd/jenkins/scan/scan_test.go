package scan

import (
	"testing"

	"github.com/CompassSecurity/pipeleek/pkg/config"
)

func TestNewScanCmd(t *testing.T) {
	cmd := NewScanCmd()
	if cmd == nil {
		t.Fatal("expected non-nil command")
	}

	if cmd.Use != "scan" {
		t.Fatalf("expected use 'scan', got %q", cmd.Use)
	}

	flags := cmd.Flags()
	for _, name := range []string{
		"jenkins",
		"username",
		"token",
		"folder",
		"job",
		"max-builds",
		"threads",
		"truffle-hog-verification",
		"confidence",
		"artifacts",
		"max-artifact-size",
	} {
		if flags.Lookup(name) == nil {
			t.Errorf("expected flag %q to exist", name)
		}
	}
}

func TestJenkinsScanFlagBindings(t *testing.T) {
	t.Setenv("PIPELEEK_NO_CONFIG", "1")

	if err := config.InitializeViper(""); err != nil {
		t.Fatalf("InitializeViper failed: %v", err)
	}

	cmd := NewScanCmd()

	flagValues := map[string]string{
		"folder": "my-folder",
		"job":    "my-job",
	}
	for flag, value := range flagValues {
		if err := cmd.Flags().Set(flag, value); err != nil {
			t.Fatalf("Failed to set flag %q: %v", flag, err)
		}
	}
	if err := cmd.Flags().Set("artifacts", "true"); err != nil {
		t.Fatalf("Failed to set artifacts flag: %v", err)
	}

	if err := config.AutoBindFlags(cmd, map[string]string{
		"jenkins":                  "jenkins.url",
		"username":                 "jenkins.username",
		"token":                    "jenkins.token",
		"folder":                   "jenkins.scan.folder",
		"job":                      "jenkins.scan.job",
		"max-builds":               "jenkins.scan.max_builds",
		"artifacts":                "jenkins.scan.artifacts",
		"threads":                  "common.threads",
		"truffle-hog-verification": "common.trufflehog_verification",
		"max-artifact-size":        "common.max_artifact_size",
		"confidence":               "common.confidence_filter",
		"hit-timeout":              "common.hit_timeout",
	}); err != nil {
		t.Fatalf("AutoBindFlags failed: %v", err)
	}

	if got := config.GetString("jenkins.scan.folder"); got != "my-folder" {
		t.Errorf("Expected jenkins.scan.folder=%q, got %q", "my-folder", got)
	}
	if got := config.GetString("jenkins.scan.job"); got != "my-job" {
		t.Errorf("Expected jenkins.scan.job=%q, got %q", "my-job", got)
	}
	if got := config.GetBool("jenkins.scan.artifacts"); !got {
		t.Error("Expected jenkins.scan.artifacts=true")
	}
}

func TestJenkinsScanEnvVarBinding(t *testing.T) {
	t.Setenv("PIPELEEK_NO_CONFIG", "1")
	t.Setenv("PIPELEEK_JENKINS_SCAN_ARTIFACTS", "true")
	t.Setenv("PIPELEEK_JENKINS_SCAN_MAX_BUILDS", "10")

	if err := config.InitializeViper(""); err != nil {
		t.Fatalf("InitializeViper failed: %v", err)
	}

	cmd := NewScanCmd()

	if err := config.AutoBindFlags(cmd, map[string]string{
		"artifacts":  "jenkins.scan.artifacts",
		"max-builds": "jenkins.scan.max_builds",
	}); err != nil {
		t.Fatalf("AutoBindFlags failed: %v", err)
	}

	if got := config.GetBool("jenkins.scan.artifacts"); !got {
		t.Errorf("Expected jenkins.scan.artifacts=true from env var, got %v", got)
	}
	if got := config.GetInt("jenkins.scan.max_builds"); got != 10 {
		t.Errorf("Expected jenkins.scan.max_builds=10 from env var, got %d", got)
	}
}

func TestJenkinsScanOptions(t *testing.T) {
	opts := JenkinsScanOptions{
		CommonScanOptions: config.CommonScanOptions{
			ConfidenceFilter:       []string{"high"},
			MaxScanGoRoutines:      5,
			TruffleHogVerification: true,
			Artifacts:              true,
		},
		JenkinsURL: "https://jenkins.example.com",
		Username:   "admin",
		Token:      "apitoken",
		Folder:     "team-a",
		Job:        "",
		MaxBuilds:  10,
	}

	if opts.JenkinsURL == "" || opts.Username == "" || opts.Token == "" {
		t.Fatal("expected required Jenkins fields to be populated")
	}
	if opts.MaxBuilds != 10 {
		t.Fatalf("expected MaxBuilds=10, got %d", opts.MaxBuilds)
	}
	if len(opts.ConfidenceFilter) != 1 || opts.ConfidenceFilter[0] != "high" {
		t.Fatalf("unexpected confidence filter: %#v", opts.ConfidenceFilter)
	}
}
