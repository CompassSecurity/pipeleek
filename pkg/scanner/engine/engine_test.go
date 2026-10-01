package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/scanner/detectors"
	"github.com/CompassSecurity/pipeleek/pkg/scanner/rules"
	"github.com/CompassSecurity/pipeleek/pkg/scanner/types"
	blconfig "github.com/betterleaks/betterleaks/v2/config"
	blreport "github.com/betterleaks/betterleaks/v2/report"
)

func init() {
	rules.InitRules([]string{})
}

func TestDetectHits(t *testing.T) {
	tests := []struct {
		name     string
		text     []byte
		wantHits bool
	}{
		{
			name:     "no secrets",
			text:     []byte("This is just plain text with no secrets"),
			wantHits: false,
		},
		{
			name:     "potential secret pattern",
			text:     []byte("GITLAB_USER_ID=12345"),
			wantHits: true,
		},
		{
			name:     "CI_REGISTRY_PASSWORD pattern",
			text:     []byte("CI_REGISTRY_PASSWORD=supersecret123"),
			wantHits: true,
		},
		{
			name:     "empty text",
			text:     []byte(""),
			wantHits: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := DetectHits(tt.text, 1, false, 60*time.Second)
			if err != nil {
				t.Fatalf("DetectHits() error = %v", err)
			}

			hasHits := len(findings) > 0
			if hasHits != tt.wantHits {
				t.Errorf("DetectHits() found hits = %v, want %v (findings: %d)", hasHits, tt.wantHits, len(findings))
			}
		})
	}
}

func TestDetectHitsWithTimeout(t *testing.T) {
	text := []byte("CI_REGISTRY_PASSWORD=supersecret123")
	result := DetectHitsWithTimeout(text, 1, false)

	if result.Error != nil {
		t.Errorf("DetectHitsWithTimeout() error = %v", result.Error)
	}

	if len(result.Findings) == 0 {
		t.Log("No findings detected, which is acceptable for this test")
	}
}

func TestDetectHits_ExplicitTimeout(t *testing.T) {
	// Test that a very short timeout causes an error and the error contains the configured timeout value
	text := []byte("CI_REGISTRY_PASSWORD=supersecret123")

	// Use 1 nanosecond timeout to guarantee timeout occurs
	shortTimeout := 1 * time.Nanosecond

	_, err := DetectHits(text, 1, false, shortTimeout)

	// With 1ns timeout, we expect this to always timeout
	if err == nil {
		t.Fatal("Expected timeout error with 1ns timeout, but got nil")
	}

	// Verify the error message contains the configured timeout value
	expectedTimeoutStr := shortTimeout.String() // "1ns"
	expectedError := "hit detection timed out (" + expectedTimeoutStr + ")"
	if err.Error() != expectedError {
		t.Errorf("Error message should contain configured timeout. Got: %q, expected: %q", err.Error(), expectedError)
	}
}

func TestDeduplicateFindings(t *testing.T) {
	finding := types.Finding{
		Pattern: types.PatternElement{
			Pattern: types.PatternPattern{
				Name:       "Test Pattern",
				Confidence: "high",
			},
		},
		Text: "secret123",
	}

	duplicateFindings := []types.Finding{finding, finding, finding}

	deduped := deduplicateFindings(duplicateFindings)

	if len(deduped) != 1 {
		t.Errorf("Expected 1 deduplicated finding, got %d", len(deduped))
	}
}

func TestExtractHitWithSurroundingText(t *testing.T) {
	tests := []struct {
		name            string
		text            []byte
		hitIndex        []int
		additionalBytes int
		wantLen         int
	}{
		{
			name:            "normal extraction",
			text:            []byte("before secret123 after"),
			hitIndex:        []int{7, 16},
			additionalBytes: 5,
			wantLen:         19,
		},
		{
			name:            "start boundary",
			text:            []byte("secret123 after"),
			hitIndex:        []int{0, 9},
			additionalBytes: 5,
			wantLen:         14,
		},
		{
			name:            "end boundary",
			text:            []byte("before secret123"),
			hitIndex:        []int{7, 16},
			additionalBytes: 5,
			wantLen:         14,
		},
		{
			name:            "zero additional bytes",
			text:            []byte("before secret123 after"),
			hitIndex:        []int{7, 16},
			additionalBytes: 0,
			wantLen:         9,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractHitWithSurroundingText(tt.text, tt.hitIndex, tt.additionalBytes)
			if len(result) != tt.wantLen {
				t.Errorf("extractHitWithSurroundingText() length = %d, want %d", len(result), tt.wantLen)
			}
		})
	}
}

func TestCleanHitLine(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "with newlines",
			input:    "line1\nline2\nline3",
			expected: "line1 line2 line3",
		},
		{
			name:     "with ANSI codes",
			input:    "\x1b[31mred text\x1b[0m",
			expected: "red text",
		},
		{
			name:     "plain text",
			input:    "plain text",
			expected: "plain text",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cleanHitLine(tt.input)
			if result != tt.expected {
				t.Errorf("cleanHitLine() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestDeduplicateFindingsWithState_NoDependencyOnGlobal verifies that the pure function
// operates without relying on package-level global state.
func TestDeduplicateFindingsWithState_NoDependencyOnGlobal(t *testing.T) {
	finding := types.Finding{
		Pattern: types.PatternElement{
			Pattern: types.PatternPattern{Name: "Pattern A", Confidence: "high"},
		},
		Text: "unique_secret_abc123",
	}

	// First call: unique finding should be included
	deduped, newState := deduplicateFindingsWithState([]types.Finding{finding}, nil)
	if len(deduped) != 1 {
		t.Fatalf("first call: expected 1 finding, got %d", len(deduped))
	}
	if len(newState) != 1 {
		t.Fatalf("expected state to have 1 entry, got %d", len(newState))
	}

	// Second call with same finding using the returned state: should be deduplicated
	deduped2, _ := deduplicateFindingsWithState([]types.Finding{finding}, newState)
	if len(deduped2) != 0 {
		t.Fatalf("second call: expected 0 findings (duplicate), got %d", len(deduped2))
	}
}

// TestDeduplicateFindingsWithState_TrimsAtLimit verifies that the seen-hash list is
// trimmed when it exceeds 500 entries (the previously untested branch).
func TestDeduplicateFindingsWithState_TrimsAtLimit(t *testing.T) {
	// Build a state that already has 500 entries
	seenHashes := make([]string, 500)
	for i := range seenHashes {
		seenHashes[i] = fmt.Sprintf("hash-%04d", i)
	}

	// Add a new unique finding: the state must grow to 501 and then be trimmed
	newFinding := types.Finding{
		Pattern: types.PatternElement{
			Pattern: types.PatternPattern{Name: "NewPattern", Confidence: "medium"},
		},
		Text: "brand_new_secret_xyz",
	}

	deduped, newState := deduplicateFindingsWithState([]types.Finding{newFinding}, seenHashes)
	if len(deduped) != 1 {
		t.Fatalf("expected 1 unique finding, got %d", len(deduped))
	}
	// After trim, length should be exactly 500 (grew to 501, first element removed)
	if len(newState) != 500 {
		t.Fatalf("expected state len 500 after trim, got %d", len(newState))
	}
}

func TestDetectHits_GitLabTokenDetection(t *testing.T) {
	// GitLab tokens should be detected by built-in rules regardless of TruffleHog
	// verification status (which only verifies against gitlab.com).
	tests := []struct {
		name  string
		text  []byte
		token string
	}{
		{
			name:  "personal access token v2",
			text:  []byte("export GITLAB_TOKEN=glpat-abcdefghij1234567890"),
			token: "glpat-",
		},
		{
			name:  "personal access token v2 max length",
			text:  []byte("export GITLAB_TOKEN=glpat-abcdefghij12345678901x"),
			token: "glpat-",
		},
		{
			name:  "personal access token v3",
			text:  []byte("export GITLAB_TOKEN=glpat-abcDEFghij1234567890_-=xyzABC0ab.ab.abc012345"),
			token: "glpat-",
		},
		{
			name:  "pipeline trigger token",
			text:  []byte("TRIGGER_TOKEN=glptt-abcdefghij1234567890"),
			token: "glptt-",
		},
		{
			name:  "deploy token",
			text:  []byte("DEPLOY_TOKEN=gldt-abcdefghij1234567890xx"),
			token: "gldt-",
		},
		{
			name:  "runner authentication token",
			text:  []byte("RUNNER_TOKEN=glrt-abcdefghij1234567890xx"),
			token: "glrt-",
		},
		{
			name:  "runner registration token",
			text:  []byte("RUNNER_TOKEN=glrtr-abcdefghij1234567890x"),
			token: "glrtr-",
		},
		{
			name:  "legacy runner token",
			text:  []byte("TOKEN=GR1348941abcdefghij1234567890"),
			token: "GR1348941",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use verification=true to prove that the built-in rules catch
			// GitLab tokens even when TruffleHog verification is active.
			findings, err := DetectHits(tt.text, 1, true, 60*time.Second)
			if err != nil {
				t.Fatalf("DetectHits() error = %v", err)
			}

			foundByBuiltinRule := false
			for _, f := range findings {
				if strings.Contains(f.Text, tt.token) && f.Pattern.Pattern.Confidence == "high" {
					foundByBuiltinRule = true
					break
				}
			}
			if !foundByBuiltinRule {
				t.Errorf("Expected GitLab token %q to be detected by built-in rule, findings: %v", tt.token, findings)
			}
		})
	}
}

func TestDetectHits_CustomGitLabDetector_WithURLSet(t *testing.T) {
	// Test that the custom GitLab detector is active when URL is set
	// This ensures GitLab tokens are detected by the custom detector
	defer detectors.ClearGitLabURL()

	testURL := "https://gitlab.example.com"
	detectors.SetGitLabURL(testURL)

	testData := []byte(`
	export GITLAB_TOKEN="glpat-abcdefghijklmnopqrst"
	`)

	findings, err := DetectHits(testData, 1, false, 60*time.Second)
	if err != nil {
		t.Fatalf("DetectHits() error = %v", err)
	}

	// Should find the token via custom detector
	found := false
	for _, f := range findings {
		if strings.Contains(f.Text, "glpat-abcdefghijklmnopqrst") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected GitLab PAT to be detected by custom detector, findings: %v", findings)
	}
}

func TestDetectHits_CustomGitLabDetector_WithoutURLSet(t *testing.T) {
	// Test that the custom GitLab detector detects tokens even without URL set
	// (it just won't verify them)
	defer detectors.ClearGitLabURL()
	detectors.ClearGitLabURL()

	testData := []byte(`
	runner_token: glrt-1234567890123456789012
	`)

	findings, err := DetectHits(testData, 1, false, 60*time.Second)
	if err != nil {
		t.Fatalf("DetectHits() error = %v", err)
	}

	// Should still find the token even without URL
	found := false
	for _, f := range findings {
		if strings.Contains(f.Text, "glrt-1234567890123456789012") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected GitLab runner token to be detected, findings: %v", findings)
	}
}

func TestDetectHits_CustomGitLabDetector_MultipleTypes(t *testing.T) {
	// Test that multiple GitLab token types are detected
	defer detectors.ClearGitLabURL()

	testData := []byte(`
	pat: glpat-abcdefghijklmnopqrst
	trigger: glptt-1234567890123456789012
	deploy: gldt-abcdefghijklmnopqrst
	`)

	findings, err := DetectHits(testData, 4, false, 60*time.Second)
	if err != nil {
		t.Fatalf("DetectHits() error = %v", err)
	}

	// Should find multiple token types
	tokenCounts := map[string]int{
		"glpat-": 0,
		"glptt-": 0,
		"gldt-":  0,
	}

	for _, f := range findings {
		for prefix := range tokenCounts {
			if strings.Contains(f.Text, prefix) {
				tokenCounts[prefix]++
			}
		}
	}

	for prefix, count := range tokenCounts {
		if count == 0 {
			t.Errorf("Expected to find token with prefix %s, but found none. All findings: %v", prefix, findings)
		}
	}
}

func TestDetectHits_BetterleaksFindingUsesExtractedValue(t *testing.T) {
	token := "glpat-bcdefghijklmnopqrstu"
	findings, err := DetectHits([]byte("GITLAB_TOKEN="+token), 1, false, 60*time.Second)
	if err != nil {
		t.Fatalf("DetectHits() error = %v", err)
	}

	for _, finding := range findings {
		if finding.Pattern.Pattern.Name == "betterleaks/gitlab-pat" {
			if finding.Text != token {
				t.Fatalf("Betterleaks finding text = %q, want extracted token %q", finding.Text, token)
			}
			return
		}
	}
	t.Fatalf("Betterleaks GitLab PAT finding not found: %v", findings)
}

func newGitLabPATServer(t *testing.T, status int, patRequests *atomic.Int32) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v4/personal_access_tokens/self" {
			patRequests.Add(1)
		}
		w.WriteHeader(status)
		if status == http.StatusOK {
			_, _ = fmt.Fprint(w, `{"id":1,"name":"fixture","user_id":1,"scopes":["api"]}`)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func TestDetectBetterleaks_ValidatesGitLabOnPublicAndSelfHosted(t *testing.T) {
	tests := []struct {
		name         string
		publicStatus int
		selfStatus   int
		wantFound    bool
	}{
		{name: "valid on self-hosted only", publicStatus: http.StatusUnauthorized, selfStatus: http.StatusOK, wantFound: true},
		{name: "valid on gitlab.com only", publicStatus: http.StatusOK, selfStatus: http.StatusUnauthorized, wantFound: true},
		{name: "invalid on both is suppressed", publicStatus: http.StatusUnauthorized, selfStatus: http.StatusUnauthorized, wantFound: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var publicRequests, selfRequests atomic.Int32
			public := newGitLabPATServer(t, tt.publicStatus, &publicRequests)
			selfHosted := newGitLabPATServer(t, tt.selfStatus, &selfRequests)

			originalPublic := publicGitLabURL
			publicGitLabURL = public.URL
			t.Cleanup(func() { publicGitLabURL = originalPublic })

			token := "glpat-cdefghijklmnopqrstuv"
			findings, err := detectBetterleaks(context.Background(), []byte("GITLAB_TOKEN="+token), 1, true, DetectionOptions{
				GitLabURL: selfHosted.URL,
				Timeout:   60 * time.Second,
			})
			if err != nil {
				t.Fatalf("detectBetterleaks() error = %v", err)
			}
			if publicRequests.Load() == 0 || selfRequests.Load() == 0 {
				t.Fatalf("expected validation on both hosts, got public=%d self-hosted=%d", publicRequests.Load(), selfRequests.Load())
			}

			var found *types.Finding
			for i := range findings {
				if findings[i].Pattern.Pattern.Name == "betterleaks/gitlab-pat" {
					found = &findings[i]
				}
			}
			if !tt.wantFound {
				if found != nil {
					t.Fatalf("expected finding rejected by both hosts to be suppressed, got %+v", *found)
				}
				return
			}
			if found == nil {
				t.Fatalf("validated Betterleaks GitLab PAT finding not found: %v", findings)
			}
			if found.Text != token || found.Pattern.Pattern.Confidence != "high-verified" {
				t.Fatalf("unexpected validated finding: %+v", *found)
			}
		})
	}
}

func TestMergeValidation(t *testing.T) {
	valid := blreport.Analysis{Status: blreport.ValidationStatusValid}
	invalid := blreport.Analysis{Status: blreport.ValidationStatusInvalid}
	revoked := blreport.Analysis{Status: blreport.ValidationStatusRevoked}
	unknown := blreport.Analysis{Status: blreport.ValidationStatusUnknown}

	tests := []struct {
		name string
		a, b blreport.Analysis
		want blreport.ValidationStatus
	}{
		{"valid wins over invalid", invalid, valid, blreport.ValidationStatusValid},
		{"valid wins over unknown", valid, unknown, blreport.ValidationStatusValid},
		{"unknown keeps finding unresolved", invalid, unknown, blreport.ValidationStatusUnknown},
		{"rejected on both stays rejected", invalid, revoked, blreport.ValidationStatusInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mergeValidation(tt.a, tt.b).Status; got != tt.want {
				t.Fatalf("mergeValidation() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDetectHitsWithOptions_BetterleaksPathRule(t *testing.T) {
	content := []byte(`administrator_login_password = "A1b2C3d4E5f6"`)
	findForPath := func(path string) []types.Finding {
		// Call detectBetterleaks directly: DetectHits dedup would mask the second call.
		findings, err := detectBetterleaks(context.Background(), content, 1, false, DetectionOptions{Path: path, Timeout: 60 * time.Second})
		if err != nil {
			t.Fatalf("detectBetterleaks(%q) error = %v", path, err)
		}
		return findings
	}
	hasRule := func(findings []types.Finding) bool {
		for _, finding := range findings {
			if finding.Pattern.Pattern.Name == "betterleaks/hashicorp-tf-password" {
				return true
			}
		}
		return false
	}

	if !hasRule(findForPath("main.tf")) {
		t.Fatal("expected Terraform password rule to match a .tf path")
	}
	if hasRule(findForPath("main.txt")) {
		t.Fatal("Terraform password rule matched a non-Terraform path")
	}
}

func TestDetectHits_SetsEngine(t *testing.T) {
	defer detectors.ClearGitLabURL()
	detectors.ClearGitLabURL()

	findings, err := DetectHits([]byte("GITLAB_TOKEN=glpat-defghijklmnopqrstuvw"), 1, false, 60*time.Second)
	if err != nil {
		t.Fatalf("DetectHits() error = %v", err)
	}

	engines := map[string]bool{}
	for _, finding := range findings {
		if finding.Engine == "" {
			t.Errorf("finding %q has no engine", finding.Pattern.Pattern.Name)
		}
		engines[finding.Engine] = true
	}
	for _, engine := range []string{EngineRules, EngineBetterleaks, EngineGitLab} {
		if !engines[engine] {
			t.Errorf("expected a finding from engine %q, got engines %v", engine, engines)
		}
	}
}

func TestMapBetterleaksFindings(t *testing.T) {
	findings := []blreport.Finding{
		{RuleID: "valid-token", Confidence: "medium", Match: blreport.Match{Full: "token=secret-value", Value: "secret-value"}, Analysis: blreport.Analysis{Status: blreport.ValidationStatusValid}},
		{RuleID: "unresolved-token", Confidence: "low", Match: blreport.Match{Full: "token=other-value", Value: "other-value"}, Analysis: blreport.Analysis{Status: blreport.ValidationStatusUnknown}},
		{RuleID: "invalid-token", Confidence: "high", Match: blreport.Match{Value: "invalid-value"}, Analysis: blreport.Analysis{Status: blreport.ValidationStatusInvalid}},
		{RuleID: "revoked-token", Confidence: "high", Match: blreport.Match{Value: "revoked-value"}, Analysis: blreport.Analysis{Status: blreport.ValidationStatusRevoked}},
	}

	mapped := mapBetterleaksFindings(findings, nil)
	if len(mapped) != 2 {
		t.Fatalf("mapped %d findings, want 2", len(mapped))
	}
	if mapped[0].Pattern.Pattern.Name != "betterleaks/valid-token" || mapped[0].Text != "secret-value" || mapped[0].Pattern.Pattern.Confidence != "high-verified" || mapped[0].Engine != EngineBetterleaks {
		t.Fatalf("unexpected validated finding mapping: %+v", mapped[0])
	}
	if mapped[1].Pattern.Pattern.Name != "betterleaks/unresolved-token" || mapped[1].Text != "other-value" || mapped[1].Pattern.Pattern.Confidence != "low" {
		t.Fatalf("unexpected unresolved finding mapping: %+v", mapped[1])
	}

	verifiedOnly := mapBetterleaksFindings(findings, []string{"high-verified"})
	if len(verifiedOnly) != 1 || verifiedOnly[0].Pattern.Pattern.Name != "betterleaks/valid-token" {
		t.Fatalf("confidence filtering returned unexpected findings: %+v", verifiedOnly)
	}
}

func TestGetBetterleaksRuntimeVerificationIsOptIn(t *testing.T) {
	runtime, err := getBetterleaksRuntime("", false, 37, 0)
	if err != nil {
		t.Fatalf("getBetterleaksRuntime() error = %v", err)
	}
	if runtime.analyzer != nil {
		t.Fatal("expected analyzer to remain uninitialized when verification is disabled")
	}
}

func TestRewriteGitLabRuleHosts(t *testing.T) {
	config, err := blconfig.Default()
	if err != nil {
		t.Fatalf("config.Default() error = %v", err)
	}
	rewriteGitLabRuleHosts(config, "https://gitlab.example.test")

	for _, rule := range config.Rules {
		if rule.ID == "gitlab-pat" {
			if !strings.Contains(rule.ValidateExpr, "https://gitlab.example.test") || !strings.Contains(rule.ValidateExpr, "/api/v4/personal_access_tokens/self") {
				t.Fatalf("GitLab PAT validator did not use the configured host: %s", rule.ValidateExpr)
			}
			if strings.Contains(rule.ValidateExpr, "https://gitlab.com") {
				t.Fatal("GitLab PAT validator still references gitlab.com")
			}
			return
		}
	}
	t.Fatal("GitLab PAT rule not found in Betterleaks default configuration")
}
