package scan

import "testing"

func TestNormalizeProjectSlug(t *testing.T) {
	tests := []struct {
		name      string
		in        string
		vcs       string
		want      string
		wantError bool
	}{
		{name: "org/repo", in: "org/repo", vcs: "github", want: "github/org/repo"},
		{name: "vcs/org/repo", in: "bitbucket/org/repo", vcs: "github", want: "bitbucket/org/repo"},
		{name: "invalid", in: "org", vcs: "github", wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeProjectSlug(tt.in, tt.vcs)
			if tt.wantError {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestBelongsToOrg(t *testing.T) {
	if !belongsToOrg("github/my-org/my-repo", "my-org") {
		t.Fatal("expected project to belong to org")
	}
	if belongsToOrg("github/other-org/my-repo", "my-org") {
		t.Fatal("expected project to not belong to org")
	}
}

func TestNormalizedOrgName(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "my-org", want: "my-org"},
		{in: "github/my-org", want: "my-org"},
		{in: "gh/my-org", want: "my-org"},
		{in: "", want: ""},
	}

	for _, tt := range tests {
		if got := normalizedOrgName(tt.in); got != tt.want {
			t.Fatalf("normalizedOrgName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestVCSFromURL(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "https://github.com/example/repo", want: "github"},
		{in: "https://bitbucket.org/example/repo", want: "bitbucket"},
		{in: "https://example.com/example/repo", want: ""},
	}

	for _, tt := range tests {
		if got := vcsFromURL(tt.in); got != tt.want {
			t.Fatalf("vcsFromURL(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestNormalizeVCSName(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "github", want: "github"},
		{in: "gh", want: "github"},
		{in: "circleci", want: "circleci"},
		{in: "bb", want: "bitbucket"},
		{in: "bitbucket", want: "bitbucket"},
	}

	for _, tt := range tests {
		if got := normalizeVCSName(tt.in); got != tt.want {
			t.Fatalf("normalizeVCSName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestCircleciUUIDSlug(t *testing.T) {
	slug, ok := circleciUUIDSlug("//circleci.com/3901667c-bcfd-4296-8bda-c5c6e35ab886/4856fff8-1113-43d7-a091-4f7950757db9")
	if !ok {
		t.Fatal("expected slug extraction to succeed")
	}

	want := "circleci/3901667c-bcfd-4296-8bda-c5c6e35ab886/4856fff8-1113-43d7-a091-4f7950757db9"
	if slug != want {
		t.Fatalf("expected %q, got %q", want, slug)
	}
}

func TestProjectSlugFromV1(t *testing.T) {
	item := v1ProjectItem{
		Username: "pipeleek",
		Reponame: "pipeleek-secrets-demo",
		VCSURL:   "//circleci.com/3901667c-bcfd-4296-8bda-c5c6e35ab886/4856fff8-1113-43d7-a091-4f7950757db9",
		VCSType:  "circleci",
	}

	slug, ok := projectSlugFromV1(item, "github")
	if !ok {
		t.Fatal("expected project slug conversion to succeed")
	}

	want := "circleci/3901667c-bcfd-4296-8bda-c5c6e35ab886/4856fff8-1113-43d7-a091-4f7950757db9"
	if slug != want {
		t.Fatalf("expected %q, got %q", want, slug)
	}
}

func TestCircleAppWorkflowURL(t *testing.T) {
	if got := circleAppWorkflowURL(""); got != "https://app.circleci.com/pipelines" {
		t.Fatalf("unexpected fallback url: %s", got)
	}

	if got := circleAppWorkflowURL("wf-123"); got != "https://app.circleci.com/pipelines/workflows/wf-123" {
		t.Fatalf("unexpected workflow url: %s", got)
	}
}

func TestCircleJobStepURL(t *testing.T) {
	fallback := "https://app.circleci.com/pipelines/workflows/wf-123"

	// empty WebURL falls back gracefully
	if got := circleJobStepURL("", 0, 0, fallback); got != fallback {
		t.Fatalf("expected fallback url, got %q", got)
	}

	// normal step link
	jobURL := "https://app.circleci.com/pipelines/workflows/wf-123/jobs/42"
	want := "https://app.circleci.com/pipelines/workflows/wf-123/jobs/42/steps/3:1"
	if got := circleJobStepURL(jobURL, 3, 1, fallback); got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}

	// trailing slash in WebURL is stripped
	if got := circleJobStepURL(jobURL+"/", 0, 0, fallback); got != jobURL+"/steps/0:0" {
		t.Fatalf("unexpected trailing-slash result: %q", got)
	}
}

func TestFlattenLogOutput(t *testing.T) {
	t.Run("json array", func(t *testing.T) {
		raw := []byte(`[{"message":"line1"},{"message":"line2"}]`)
		got := string(flattenLogOutput(raw))
		if got != "line1\nline2\n" {
			t.Fatalf("unexpected flattened output: %q", got)
		}
	})

	t.Run("json object", func(t *testing.T) {
		raw := []byte(`{"message":"single-line"}`)
		got := string(flattenLogOutput(raw))
		if got != "single-line" {
			t.Fatalf("unexpected flattened output: %q", got)
		}
	})

	t.Run("plain text", func(t *testing.T) {
		raw := []byte("  hello secrets  \n")
		got := string(flattenLogOutput(raw))
		if got != "hello secrets" {
			t.Fatalf("unexpected flattened output: %q", got)
		}
	})
}
