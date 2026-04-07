package scan

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
)

func TestListOrganizationProjectsCandidateFallback(t *testing.T) {
	var (
		mu       sync.Mutex
		requests []string
	)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.URL.Path)
		mu.Unlock()

		switch r.URL.Path {
		case "/api/v2/me/collaborations":
			// Return empty — no UUID resolution available in this test scenario.
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[]`))
		case "/api/v2/organization/my-org/project":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"not found"}`))
		case "/api/v2/organization/github/my-org/project":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"items":[{"slug":"my-org/repo-a"},{"slug":"bitbucket/other/repo-b"}],"next_page_token":""}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	baseURL, err := url.Parse(ts.URL + "/api/v2/")
	if err != nil {
		t.Fatalf("failed to parse base url: %v", err)
	}

	client := newCircleAPIClient(baseURL, "token", ts.Client())
	projects, err := client.ListOrganizationProjects(context.Background(), "my-org", "github")
	if err != nil {
		t.Fatalf("expected fallback candidate lookup to succeed, got error: %v", err)
	}

	if len(projects) != 2 {
		t.Fatalf("expected 2 projects, got %d: %#v", len(projects), projects)
	}
	if projects[0] != "github/my-org/repo-a" {
		t.Fatalf("unexpected first project: %q", projects[0])
	}
	if projects[1] != "bitbucket/other/repo-b" {
		t.Fatalf("unexpected second project: %q", projects[1])
	}

	mu.Lock()
	defer mu.Unlock()
	// requests[0] = me/collaborations (UUID resolution attempt)
	// requests[1] = organization/my-org/project (first slug candidate, 404)
	// requests[2] = organization/github/my-org/project (VCS-prefixed candidate, succeeds)
	if len(requests) < 3 {
		t.Fatalf("expected at least 3 requests, got %d: %v", len(requests), requests)
	}
	if requests[0] != "/api/v2/me/collaborations" {
		t.Fatalf("expected collaborations request first, got %q", requests[0])
	}
	if requests[1] != "/api/v2/organization/my-org/project" {
		t.Fatalf("expected first candidate request path, got %q", requests[1])
	}
	if requests[2] != "/api/v2/organization/github/my-org/project" {
		t.Fatalf("expected second candidate request path, got %q", requests[2])
	}
}

func TestListOrganizationProjectsCollaborationUUIDResolution(t *testing.T) {
	const orgUUID = "96df906d-3617-46fd-96d0-8f80a8c4d00a"
	const orgSlug = "circleci/KdZvpc432VpdV8UBajzc9f"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v2/me/collaborations":
			payload := []collaborationItem{{
				ID:      orgUUID,
				Slug:    orgSlug,
				Name:    "My Org",
				VCSType: "circleci",
			}}
			_ = json.NewEncoder(w).Encode(payload)
		case "/api/v2/organization/" + orgSlug + "/project":
			// slug-based call fails — UUID not accepted at this path
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"not found"}`))
		case "/api/v2/organization/" + orgUUID + "/project":
			// UUID-based call succeeds
			_, _ = w.Write([]byte(`{"items":[{"slug":"github/my-org/repo-a"}],"next_page_token":""}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	baseURL, err := url.Parse(ts.URL + "/api/v2/")
	if err != nil {
		t.Fatalf("failed to parse base url: %v", err)
	}

	client := newCircleAPIClient(baseURL, "token", ts.Client())
	projects, err := client.ListOrganizationProjects(context.Background(), orgSlug, "github")
	if err != nil {
		t.Fatalf("expected UUID-resolution to succeed, got error: %v", err)
	}
	if len(projects) != 1 || projects[0] != "github/my-org/repo-a" {
		t.Fatalf("unexpected projects: %#v", projects)
	}
}

func TestListOrganizationProjectsPrefixedOrgFallback(t *testing.T) {
	var requests []string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.Path)
		switch r.URL.Path {
		case "/api/v2/me/collaborations":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[]`))
		case "/api/v2/organization/github/storybookjs/project":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"not found"}`))
		case "/api/v2/organization/storybookjs/project":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"items":[{"slug":"storybookjs/repo-a"}],"next_page_token":""}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	baseURL, err := url.Parse(ts.URL + "/api/v2/")
	if err != nil {
		t.Fatalf("failed to parse base url: %v", err)
	}

	client := newCircleAPIClient(baseURL, "token", ts.Client())
	projects, err := client.ListOrganizationProjects(context.Background(), "github/storybookjs", "github")
	if err != nil {
		t.Fatalf("expected prefixed fallback to succeed, got error: %v", err)
	}
	if len(projects) != 1 || projects[0] != "github/storybookjs/repo-a" {
		t.Fatalf("unexpected projects: %#v", projects)
	}

	if len(requests) < 3 {
		t.Fatalf("expected at least 3 requests, got %d (%v)", len(requests), requests)
	}
	if requests[1] != "/api/v2/organization/github/storybookjs/project" {
		t.Fatalf("unexpected first org candidate request: %q", requests[1])
	}
	if requests[2] != "/api/v2/organization/storybookjs/project" {
		t.Fatalf("unexpected fallback org candidate request: %q", requests[2])
	}
}

func TestListAccessibleProjectsV1FiltersAndNormalizes(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1.1/projects" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		payload := []v1ProjectItem{
			{Username: "team", Reponame: "repo-a", VCSType: "github", VCSURL: "https://github.com/team/repo-a"},
			{Username: "other", Reponame: "repo-z", VCSType: "github", VCSURL: "https://github.com/other/repo-z"},
			{Username: "team", Reponame: "ignored", VCSType: "circleci", VCSURL: "//circleci.com/org-uuid/proj-uuid"},
		}
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer ts.Close()

	baseURL, err := url.Parse(ts.URL + "/api/v2/")
	if err != nil {
		t.Fatalf("failed to parse base url: %v", err)
	}

	client := newCircleAPIClient(baseURL, "token", ts.Client())
	projects, err := client.ListAccessibleProjectsV1(context.Background(), "github", "team")
	if err != nil {
		t.Fatalf("expected v1 discovery to succeed, got error: %v", err)
	}

	if len(projects) != 2 {
		t.Fatalf("expected 2 filtered projects, got %d: %#v", len(projects), projects)
	}
	if projects[0] != "github/team/repo-a" {
		t.Fatalf("unexpected first project: %q", projects[0])
	}
	if projects[1] != "circleci/org-uuid/proj-uuid" {
		t.Fatalf("unexpected second project: %q", projects[1])
	}
}
