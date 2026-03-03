package engine

import (
	"fmt"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/scanner/rules"
	"github.com/CompassSecurity/pipeleek/pkg/scanner/types"
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
