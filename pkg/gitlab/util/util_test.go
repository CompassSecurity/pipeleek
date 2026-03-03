package util

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/CompassSecurity/pipeleek/pkg/httpclient"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// TestDetermineVersion_ParsesVersion ensures the help page parsing extracts instance_version.
func TestDetermineVersion_ParsesVersion(t *testing.T) {
	// Simulate GitLab /help endpoint content containing instance_version JSON fragment
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><script>var gon={"instance_version":"16.5.1"}</script></html>`))
	}))
	defer srv.Close()

	meta := DetermineVersion(srv.URL, "")
	if meta.Version != "16.5.1" {
		t.Fatalf("expected version 16.5.1, got %s", meta.Version)
	}
	if meta.Revision != "none" || meta.Enterprise != false {
		t.Fatalf("unexpected revision/enterprise flags: %+v", meta)
	}
}

// TestDetermineVersion_FallbackWhenMissing ensures missing version returns none.
func TestDetermineVersion_FallbackWhenMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body>No version here</body></html>`))
	}))
	defer srv.Close()

	meta := DetermineVersion(srv.URL, "")
	if meta.Version != "none" {
		t.Fatalf("expected version none, got %s", meta.Version)
	}
}

// TestFetchCICDYml_MissingFile ensures the function returns the correct error message when no .gitlab-ci.yml exists.
func TestFetchCICDYml_MissingFile(t *testing.T) {
	// Simulate GitLab API lint endpoint returning "Please provide content of" error
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/api/v4/projects/") && strings.Contains(r.URL.Path, "/ci/lint") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			response := map[string]interface{}{
				"valid":  false,
				"errors": []string{"Please provide content of .gitlab-ci.yml"},
			}
			_ = json.NewEncoder(w).Encode(response)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client, err := gitlab.NewClient("test-token", gitlab.WithBaseURL(srv.URL))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	_, err = FetchCICDYml(client, 123)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	expectedMsg := "project does most certainly not have a .gitlab-ci.yml file"
	if !strings.Contains(err.Error(), expectedMsg) {
		t.Fatalf("expected error to contain %q, got %q", expectedMsg, err.Error())
	}
}

// TestFetchCICDYml_ValidYAML ensures the function returns merged YAML when valid.
func TestFetchCICDYml_ValidYAML(t *testing.T) {
	expectedYAML := "stages:\n  - test\ntest-job:\n  script:\n    - echo test"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/api/v4/projects/") && strings.Contains(r.URL.Path, "/ci/lint") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			response := map[string]interface{}{
				"valid":       true,
				"errors":      []string{},
				"warnings":    []string{},
				"merged_yaml": expectedYAML,
			}
			_ = json.NewEncoder(w).Encode(response)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client, err := gitlab.NewClient("test-token", gitlab.WithBaseURL(srv.URL))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	yaml, err := FetchCICDYml(client, 123)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if yaml != expectedYAML {
		t.Fatalf("expected YAML %q, got %q", expectedYAML, yaml)
	}
}

// TestFetchCICDYml_OtherError ensures other validation errors are returned.
func TestFetchCICDYml_OtherError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/api/v4/projects/") && strings.Contains(r.URL.Path, "/ci/lint") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			response := map[string]interface{}{
				"valid":  false,
				"errors": []string{"syntax error on line 5"},
			}
			_ = json.NewEncoder(w).Encode(response)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client, err := gitlab.NewClient("test-token", gitlab.WithBaseURL(srv.URL))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	_, err = FetchCICDYml(client, 123)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "syntax error on line 5") {
		t.Fatalf("expected error to contain syntax error, got %q", err.Error())
	}
}

// TestIterateProjects ensures pagination calls the callback for each project.
func TestIterateProjects(t *testing.T) {
	// Build two pages of projects; page 2 has NextPage=0 to terminate pagination.
	page1 := []*gitlab.Project{
		{ID: 1, Name: "project-one"},
		{ID: 2, Name: "project-two"},
	}
	page2 := []*gitlab.Project{
		{ID: 3, Name: "project-three"},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/api/v4/projects") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		pageParam := r.URL.Query().Get("page")
		if pageParam == "2" {
			// Last page – no X-Next-Page header
			_ = json.NewEncoder(w).Encode(page2)
		} else {
			w.Header().Set("X-Next-Page", "2")
			_ = json.NewEncoder(w).Encode(page1)
		}
	}))
	defer srv.Close()

	client, err := gitlab.NewClient("token", gitlab.WithBaseURL(srv.URL))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	var seen []int64
	opts := &gitlab.ListProjectsOptions{}
	err = IterateProjects(client, opts, func(p *gitlab.Project) error {
		seen = append(seen, p.ID)
		return nil
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(seen) != 3 {
		t.Fatalf("expected 3 projects, got %d", len(seen))
	}
}

// TestIterateProjects_CallbackError ensures iteration stops on callback error.
func TestIterateProjects_CallbackError(t *testing.T) {
	projects := []*gitlab.Project{{ID: 1, Name: "p1"}, {ID: 2, Name: "p2"}}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(projects)
	}))
	defer srv.Close()

	client, err := gitlab.NewClient("token", gitlab.WithBaseURL(srv.URL))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	callCount := 0
	opts := &gitlab.ListProjectsOptions{}
	err = IterateProjects(client, opts, func(p *gitlab.Project) error {
		callCount++
		return fmt.Errorf("stop iteration")
	})

	if err == nil {
		t.Fatal("expected callback error to propagate")
	}
	if callCount != 1 {
		t.Fatalf("expected callback called once before error, got %d", callCount)
	}
}

// TestIterateGroupProjects ensures pagination calls the callback for each group project.
func TestIterateGroupProjects(t *testing.T) {
	page1 := []*gitlab.Project{
		{ID: 10, Name: "group-project-one"},
		{ID: 11, Name: "group-project-two"},
	}
	page2 := []*gitlab.Project{
		{ID: 12, Name: "group-project-three"},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/api/v4/groups/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		pageParam := r.URL.Query().Get("page")
		if pageParam == "2" {
			_ = json.NewEncoder(w).Encode(page2)
		} else {
			w.Header().Set("X-Next-Page", "2")
			_ = json.NewEncoder(w).Encode(page1)
		}
	}))
	defer srv.Close()

	client, err := gitlab.NewClient("token", gitlab.WithBaseURL(srv.URL))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	var seen []int64
	opts := &gitlab.ListGroupProjectsOptions{}
	err = IterateGroupProjects(client, "my-group", opts, func(p *gitlab.Project) error {
		seen = append(seen, p.ID)
		return nil
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(seen) != 3 {
		t.Fatalf("expected 3 projects, got %d", len(seen))
	}
}

// TestIterateGroupProjects_CallbackError ensures iteration stops on callback error.
func TestIterateGroupProjects_CallbackError(t *testing.T) {
	projects := []*gitlab.Project{{ID: 10, Name: "gp1"}}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(projects)
	}))
	defer srv.Close()

	client, err := gitlab.NewClient("token", gitlab.WithBaseURL(srv.URL))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	opts := &gitlab.ListGroupProjectsOptions{}
	err = IterateGroupProjects(client, "my-group", opts, func(p *gitlab.Project) error {
		return fmt.Errorf("stop iteration")
	})

	if err == nil {
		t.Fatal("expected callback error to propagate")
	}
}

// TestFetchVersionFromHTML verifies that fetchVersionFromHTML correctly parses the version
// from a mock /help HTML page response.
func TestFetchVersionFromHTML_ParsesVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><script>var gon={"instance_version":"17.2.1"}</script></html>`))
	}))
	defer srv.Close()

	client := httpclient.GetPipeleekHTTPClient("", nil, nil)
	meta := fetchVersionFromHTML(srv.URL, client)
	if meta.Version != "17.2.1" {
		t.Fatalf("expected version 17.2.1, got %s", meta.Version)
	}
}

// TestFetchVersionFromHTML_NoVersion verifies fallback when version is not found.
func TestFetchVersionFromHTML_NoVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body>No version here</body></html>`))
	}))
	defer srv.Close()

	client := httpclient.GetPipeleekHTTPClient("", nil, nil)
	meta := fetchVersionFromHTML(srv.URL, client)
	if meta.Version != "none" {
		t.Fatalf("expected 'none' version, got %s", meta.Version)
	}
}

// TestFetchVersionFromHTML_BadURL verifies fallback when URL cannot be parsed.
func TestFetchVersionFromHTML_BadURL(t *testing.T) {
	client := httpclient.GetPipeleekHTTPClient("", nil, nil)
	meta := fetchVersionFromHTML("://bad-url", client)
	if meta.Version != "none" {
		t.Fatalf("expected 'none' version, got %s", meta.Version)
	}
}

// TestFetchVersionFromHTML_Unreachable verifies fallback when HTTP request fails.
func TestFetchVersionFromHTML_Unreachable(t *testing.T) {
	client := httpclient.GetPipeleekHTTPClient("", nil, nil)
	meta := fetchVersionFromHTML("http://127.0.0.1:0", client)
	if meta.Version != "none" {
		t.Fatalf("expected 'none' version, got %s", meta.Version)
	}
}
