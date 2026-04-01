package scan

import (
	"testing"
	"time"
)

func TestInitializeOptions(t *testing.T) {
	opts, err := InitializeOptions(
		"admin",
		"token",
		"https://jenkins.example.com",
		"team-a",
		"",
		"100Mb",
		true,
		true,
		20,
		4,
		[]string{"high"},
		30*time.Second,
	)
	if err != nil {
		t.Fatalf("InitializeOptions returned error: %v", err)
	}

	if opts.Username != "admin" || opts.Token != "token" {
		t.Fatalf("unexpected credentials in options: %+v", opts)
	}
	if opts.JenkinsURL != "https://jenkins.example.com" {
		t.Fatalf("unexpected JenkinsURL: %s", opts.JenkinsURL)
	}
	if opts.MaxBuilds != 20 {
		t.Fatalf("unexpected MaxBuilds: %d", opts.MaxBuilds)
	}
	if opts.MaxArtifactSize <= 0 {
		t.Fatalf("expected parsed MaxArtifactSize > 0, got %d", opts.MaxArtifactSize)
	}
	if opts.Client == nil {
		t.Fatal("expected client to be initialized")
	}
}

func TestDedupeAndSort(t *testing.T) {
	got := dedupeAndSort([]string{"b/job", "a/job", "b/job"})
	if len(got) != 2 || got[0] != "a/job" || got[1] != "b/job" {
		t.Fatalf("unexpected dedupeAndSort output: %#v", got)
	}
}

func TestIsFolderClass(t *testing.T) {
	if !isFolderClass("com.cloudbees.hudson.plugins.folder.Folder") {
		t.Fatal("expected folder class to be detected")
	}
	if isFolderClass("hudson.model.FreeStyleProject") {
		t.Fatal("did not expect freestyle project to be detected as folder")
	}
}
