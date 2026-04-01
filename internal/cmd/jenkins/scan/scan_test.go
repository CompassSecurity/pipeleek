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
