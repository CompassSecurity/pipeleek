package scan

import "testing"

func TestNormalizeBaseURL(t *testing.T) {
	tests := []struct {
		name string
		in   string
		out  string
	}{
		{name: "empty", in: "", out: "http://localhost:8080/"},
		{name: "without trailing slash", in: "https://jenkins.example.com", out: "https://jenkins.example.com/"},
		{name: "with path", in: "https://jenkins.example.com/jenkins", out: "https://jenkins.example.com/jenkins/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeBaseURL(tt.in)
			if got != tt.out {
				t.Fatalf("normalizeBaseURL(%q) = %q, want %q", tt.in, got, tt.out)
			}
		})
	}
}

func TestSplitJenkinsPath(t *testing.T) {
	got := splitJenkinsPath("/team-a/service-a/")
	if len(got) != 2 || got[0] != "team-a" || got[1] != "service-a" {
		t.Fatalf("unexpected split result: %#v", got)
	}
}
