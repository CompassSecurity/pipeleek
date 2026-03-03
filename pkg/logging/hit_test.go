package logging

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func TestHit(t *testing.T) {
	// Save original logger
	originalLogger := log.Logger
	defer func() { log.Logger = originalLogger }()

	// Capture log output
	var buf bytes.Buffer

	// Setup a new logger with our HitLevelWriter
	hitWriter := NewHitLevelWriter(&buf)
	logger := zerolog.New(hitWriter).With().Timestamp().Logger()

	// Set both the global logger and writer to prevent setupGlobalHitWriter from interfering
	log.Logger = logger
	globalHitWriter = hitWriter

	// Log a hit
	Hit().Str("ruleName", "test-rule").Str("value", "secret").Msg("HIT")

	// Get the output
	output := buf.Bytes()
	if len(output) == 0 {
		t.Fatal("No output captured")
	}

	// Parse the output - take only the last valid JSON line
	lines := bytes.Split(output, []byte("\n"))
	var lastValidLine []byte
	for _, line := range lines {
		if len(line) > 0 {
			lastValidLine = line
		}
	}

	if len(lastValidLine) == 0 {
		t.Fatalf("No valid JSON line found in output: %s", string(output))
	}

	var logEntry map[string]interface{}
	err := json.Unmarshal(lastValidLine, &logEntry)
	if err != nil {
		t.Fatalf("Failed to parse log output: %v\nOutput: %s", err, string(lastValidLine))
	}

	// Verify the level is "hit"
	if logEntry["level"] != "hit" {
		t.Errorf("Expected level to be 'hit', got '%v'", logEntry["level"])
	}

	// Verify other fields
	if logEntry["ruleName"] != "test-rule" {
		t.Errorf("Expected ruleName to be 'test-rule', got '%v'", logEntry["ruleName"])
	}

	if logEntry["value"] != "secret" {
		t.Errorf("Expected value to be 'secret', got '%v'", logEntry["value"])
	}

	if logEntry["message"] != "HIT" {
		t.Errorf("Expected message to be 'HIT', got '%v'", logEntry["message"])
	}

	// Verify _hit marker is removed
	if _, exists := logEntry["_hit"]; exists {
		t.Error("Internal _hit marker should be removed from output")
	}
}

func TestHitEvent_Str(t *testing.T) {
	var buf bytes.Buffer
	hitWriter := NewHitLevelWriter(&buf)
	logger := zerolog.New(hitWriter).With().Logger()
	log.Logger = logger

	globalHitWriter = hitWriter

	Hit().Str("key1", "value1").Str("key2", "value2").Msg("Test message")

	var logEntry map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &logEntry)
	if err != nil {
		t.Fatalf("Failed to parse log output: %v", err)
	}

	if logEntry["level"] != "hit" {
		t.Errorf("Expected level 'hit', got '%v'", logEntry["level"])
	}

	if logEntry["key1"] != "value1" {
		t.Errorf("Expected key1='value1', got '%v'", logEntry["key1"])
	}

	if logEntry["key2"] != "value2" {
		t.Errorf("Expected key2='value2', got '%v'", logEntry["key2"])
	}
}

func TestHitEvent_Int(t *testing.T) {
	var buf bytes.Buffer
	hitWriter := NewHitLevelWriter(&buf)
	logger := zerolog.New(hitWriter).With().Logger()
	log.Logger = logger

	globalHitWriter = hitWriter

	Hit().Int("count", 42).Msg("Test message")

	var logEntry map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &logEntry)
	if err != nil {
		t.Fatalf("Failed to parse log output: %v", err)
	}

	if logEntry["level"] != "hit" {
		t.Errorf("Expected level 'hit', got '%v'", logEntry["level"])
	}

	// JSON numbers are float64
	if count, ok := logEntry["count"].(float64); !ok || count != 42 {
		t.Errorf("Expected count=42, got '%v'", logEntry["count"])
	}
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  zerolog.Level
		expectErr bool
	}{
		{
			name:      "parse hit level",
			input:     "hit",
			expected:  HitLevel,
			expectErr: false,
		},
		{
			name:      "parse debug level",
			input:     "debug",
			expected:  zerolog.DebugLevel,
			expectErr: false,
		},
		{
			name:      "parse info level",
			input:     "info",
			expected:  zerolog.InfoLevel,
			expectErr: false,
		},
		{
			name:      "parse warn level",
			input:     "warn",
			expected:  zerolog.WarnLevel,
			expectErr: false,
		},
		{
			name:      "parse invalid level",
			input:     "invalid",
			expected:  zerolog.NoLevel,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			level, err := ParseLevel(tt.input)

			if tt.expectErr && err == nil {
				t.Error("Expected error but got none")
			}

			if !tt.expectErr && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if level != tt.expected {
				t.Errorf("Expected level %v, got %v", tt.expected, level)
			}
		})
	}
}

func TestHitLevelWriter_Write(t *testing.T) {
	tests := []struct {
		name           string
		markAsHit      bool
		input          string
		expectedLevel  string
		expectedHasHit bool
	}{
		{
			name:           "normal warn log",
			markAsHit:      false,
			input:          `{"level":"warn","message":"test"}` + "\n",
			expectedLevel:  "warn",
			expectedHasHit: false,
		},
		{
			name:           "hit marked log",
			markAsHit:      true,
			input:          `{"level":"warn","_hit":true,"message":"test"}` + "\n",
			expectedLevel:  "hit",
			expectedHasHit: false, // _hit should be removed
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			writer := NewHitLevelWriter(&buf)

			if tt.markAsHit {
				writer.markNextAsHit()
			}

			_, err := writer.Write([]byte(tt.input))
			if err != nil {
				t.Fatalf("Write failed: %v", err)
			}

			var logEntry map[string]interface{}
			err = json.Unmarshal(buf.Bytes(), &logEntry)
			if err != nil {
				t.Fatalf("Failed to parse output: %v", err)
			}

			if logEntry["level"] != tt.expectedLevel {
				t.Errorf("Expected level '%s', got '%v'", tt.expectedLevel, logEntry["level"])
			}

			if _, hasHit := logEntry["_hit"]; hasHit != tt.expectedHasHit {
				t.Errorf("Expected _hit presence to be %v, got %v", tt.expectedHasHit, hasHit)
			}
		})
	}
}

func TestHitLevelWriter_NonJSONPassthrough(t *testing.T) {
	buf := &bytes.Buffer{}
	writer := NewHitLevelWriter(buf)

	writer.markNextAsHit()
	plainText := []byte("plain text log\n")
	n, err := writer.Write(plainText)

	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(plainText) {
		t.Errorf("expected %d bytes written, got %d", len(plainText), n)
	}
	if buf.String() != string(plainText) {
		t.Errorf("expected passthrough of non-JSON, got %s", buf.String())
	}
}

func TestHitLevelWriter_ConcurrentAccess(t *testing.T) {
	buf := &bytes.Buffer{}
	writer := NewHitLevelWriter(buf)

	// Simulate concurrent marks
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			writer.markNextAsHit()
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	// No panic = mutex protected correctly
}

func TestHitEvent_Bool(t *testing.T) {
	var buf bytes.Buffer
	hitWriter := NewHitLevelWriter(&buf)
	logger := zerolog.New(hitWriter).With().Logger()
	log.Logger = logger
	globalHitWriter = hitWriter

	Hit().Bool("isSecret", true).Msg("Test bool field")

	var logEntry map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &logEntry)
	if err != nil {
		t.Fatalf("Failed to parse log output: %v", err)
	}

	if logEntry["level"] != "hit" {
		t.Errorf("Expected level 'hit', got '%v'", logEntry["level"])
	}

	if val, ok := logEntry["isSecret"].(bool); !ok || !val {
		t.Errorf("Expected isSecret=true, got '%v'", logEntry["isSecret"])
	}
}

func TestHitEvent_Err(t *testing.T) {
	var buf bytes.Buffer
	hitWriter := NewHitLevelWriter(&buf)
	logger := zerolog.New(hitWriter).With().Logger()
	log.Logger = logger
	globalHitWriter = hitWriter

	Hit().Err(nil).Msg("Test nil error")

	var logEntry map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &logEntry)
	if err != nil {
		t.Fatalf("Failed to parse log output: %v", err)
	}

	if logEntry["level"] != "hit" {
		t.Errorf("Expected level 'hit', got '%v'", logEntry["level"])
	}
}

func TestHitLevelWriter_SetOutput(t *testing.T) {
	buf1 := &bytes.Buffer{}
	buf2 := &bytes.Buffer{}

	writer := NewHitLevelWriter(buf1)
	writer.SetOutput(buf2)

	_, err := writer.Write([]byte("test output\n"))
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	if buf2.String() != "test output\n" {
		t.Errorf("Expected output to go to buf2, got: %q", buf2.String())
	}
	if buf1.Len() != 0 {
		t.Error("Expected buf1 to be empty after SetOutput")
	}
}

func TestSetGlobalHitWriter(t *testing.T) {
	// Save original
	original := globalHitWriter
	defer func() { globalHitWriter = original }()

	buf := &bytes.Buffer{}
	writer := NewHitLevelWriter(buf)
	SetGlobalHitWriter(writer)

	if globalHitWriter != writer {
		t.Error("Expected globalHitWriter to be the new writer")
	}
}
