package archive

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractPrintableStrings(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		minLength   int
		expected    []string
		description string
	}{
		{
			name:        "simple ASCII string",
			input:       []byte("Hello World"),
			minLength:   4,
			expected:    []string{"Hello World"},
			description: "Should extract simple ASCII string",
		},
		{
			name:        "binary with embedded string",
			input:       []byte{0x00, 0x01, 0x02, 'H', 'e', 'l', 'l', 'o', 0x00, 0x01},
			minLength:   4,
			expected:    []string{"Hello"},
			description: "Should extract string from binary data",
		},
		{
			name:        "multiple strings",
			input:       []byte{0x00, 'T', 'e', 's', 't', 0x00, 0xFF, 'D', 'a', 't', 'a', 0x00},
			minLength:   4,
			expected:    []string{"Test", "Data"},
			description: "Should extract multiple strings",
		},
		{
			name:        "string too short",
			input:       []byte{0x00, 'A', 'B', 0x00, 'L', 'o', 'n', 'g', 'e', 'r', 0x00},
			minLength:   4,
			expected:    []string{"Longer"},
			description: "Should ignore strings shorter than minLength",
		},
		{
			name:        "secret in binary",
			input:       []byte{0x00, 0x01, 'A', 'P', 'I', '_', 'K', 'E', 'Y', '=', '1', '2', '3', '4', '5', 0x00, 0xFF},
			minLength:   4,
			expected:    []string{"API_KEY=12345"},
			description: "Should extract API keys from binary data",
		},
		{
			name:        "URL in binary",
			input:       []byte{0xFF, 0xFE, 'h', 't', 't', 'p', 's', ':', '/', '/', 'a', 'p', 'i', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x00},
			minLength:   4,
			expected:    []string{"https://api.example.com"},
			description: "Should extract URLs from binary data",
		},
		{
			name:        "empty input",
			input:       []byte{},
			minLength:   4,
			expected:    []string{},
			description: "Should handle empty input",
		},
		{
			name:        "only binary data",
			input:       []byte{0x00, 0x01, 0x02, 0xFF, 0xFE},
			minLength:   4,
			expected:    []string{},
			description: "Should return nothing for pure binary",
		},
		{
			name:        "string with tab and newline",
			input:       []byte{'H', 'e', 'l', 'l', 'o', '\t', 'W', 'o', 'r', 'l', 'd', '\n', 't', 'e', 's', 't'},
			minLength:   4,
			expected:    []string{"Hello\tWorld", "test"},
			description: "Should preserve tabs in strings, but newlines separate strings",
		},
		{
			name:        "custom min length",
			input:       []byte{0x00, 'A', 'B', 'C', 0x00, 'D', 'E', 'F', 'G', 'H', 0x00},
			minLength:   5,
			expected:    []string{"DEFGH"},
			description: "Should respect custom minLength",
		},
		{
			name:        "zero min length uses default",
			input:       []byte{0x00, 'T', 'e', 's', 't', 0x00},
			minLength:   0,
			expected:    []string{"Test"},
			description: "Should use default minLength when 0 is provided",
		},
		{
			name:        "string at start",
			input:       []byte{'S', 't', 'a', 'r', 't', 0x00, 0xFF},
			minLength:   4,
			expected:    []string{"Start"},
			description: "Should handle string at the start of data",
		},
		{
			name:        "string at end",
			input:       []byte{0x00, 0xFF, 'E', 'n', 'd', 'i', 'n', 'g'},
			minLength:   4,
			expected:    []string{"Ending"},
			description: "Should handle string at the end of data",
		},
		{
			name:        "JSON in binary",
			input:       []byte{0x00, '{', '"', 'k', 'e', 'y', '"', ':', '"', 'v', 'a', 'l', 'u', 'e', '"', '}', 0x00},
			minLength:   4,
			expected:    []string{`{"key":"value"}`},
			description: "Should extract JSON from binary data",
		},
		{
			name:        "multiple short strings",
			input:       []byte{0x00, 'A', 'B', 0x00, 'C', 'D', 0x00, 'E', 'F', 0x00},
			minLength:   4,
			expected:    []string{},
			description: "Should filter out all strings shorter than minLength",
		},
		{
			name:        "mixed ASCII and special chars",
			input:       []byte{'P', 'a', 's', 's', 'w', 'o', 'r', 'd', ':', 0x00, 's', 'e', 'c', 'r', 'e', 't', '1', '2', '3', '!', 0x00},
			minLength:   4,
			expected:    []string{"Password:", "secret123!"},
			description: "Should handle special characters in strings",
		},
		{
			name:        "base64-like string",
			input:       []byte{0xFF, 'Q', 'W', 'x', 'h', 'Z', 'G', 'R', 'p', 'b', 'j', 'p', 'w', 'Y', 'X', 'N', 'z', 'd', '2', '9', 'y', 'Z', 'A', '=', '=', 0x00},
			minLength:   4,
			expected:    []string{"QWxhZGRpbjpwYXNzd29yZA=="},
			description: "Should extract base64-encoded strings",
		},
		{
			name: "ELF binary header simulation",
			input: []byte{
				0x7F, 'E', 'L', 'F', // ELF magic number
				0x02, 0x01, 0x01, 0x00, // ELF header
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				'/', 'u', 's', 'r', '/', 'b', 'i', 'n', '/', 'p', 'y', 't', 'h', 'o', 'n', // String in binary
				0x00, 0x00,
			},
			minLength: 4,
			expected:  []string{"/usr/bin/python"},
			description: "Should extract paths from ELF-like binary",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractPrintableStrings(tt.input, tt.minLength)
			
			// Split result by newlines and filter empty strings
			resultStrings := []string{}
			for _, s := range strings.Split(string(result), "\n") {
				if s != "" {
					resultStrings = append(resultStrings, s)
				}
			}

			assert.Equal(t, tt.expected, resultStrings, tt.description)
		})
	}
}

func TestExtractPrintableStrings_LargeBinary(t *testing.T) {
	// Create a large binary file with embedded secrets
	var largeBinary bytes.Buffer
	
	// Write some binary data
	for i := 0; i < 1000; i++ {
		largeBinary.WriteByte(byte(i % 256))
	}
	
	// Embed a secret
	secret := "GITLAB_TOKEN=glpat-xxxxxxxxxxxxxxxxxxxx"
	largeBinary.WriteString(secret)
	
	// More binary data
	for i := 0; i < 1000; i++ {
		largeBinary.WriteByte(byte(i % 256))
	}

	result := ExtractPrintableStrings(largeBinary.Bytes(), 4)
	resultStr := string(result)
	
	assert.Contains(t, resultStr, secret, "Should extract secret from large binary file")
}

func TestExtractPrintableStrings_ASCII(t *testing.T) {
	// Test with ASCII-only strings (UTF-8 bytes are treated as non-printable)
	input := []byte{0x00, 'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', 0x00}
	result := ExtractPrintableStrings(input, 4)
	
	resultStr := string(bytes.TrimSpace(result))
	assert.Contains(t, resultStr, "Hello World", "Should extract ASCII strings")
}

func TestExtractPrintableStrings_RealWorldBinary(t *testing.T) {
	// Simulate a real-world scenario: a compiled binary with embedded config
	binary := []byte{
		// Some binary header
		0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
		// Embedded configuration URL
		'h', 't', 't', 'p', 's', ':', '/', '/', 'a', 'p', 'i', '.', 'g', 'i', 't', 'l', 'a', 'b', '.', 'c', 'o', 'm',
		0x00, 0x00,
		// More binary
		0xFF, 0xFE, 0xFD, 0xFC,
		// Embedded token
		'g', 'l', 'p', 'a', 't', '-', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
		0x00, 0x00,
	}

	result := ExtractPrintableStrings(binary, 4)
	resultStr := string(result)
	
	assert.Contains(t, resultStr, "https://api.gitlab.com", "Should extract API URL")
	assert.Contains(t, resultStr, "glpat-", "Should extract GitLab token prefix")
}

func TestExtractPrintableStrings_EdgeCases(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		result := ExtractPrintableStrings(nil, 4)
		assert.Empty(t, result, "Should handle nil input")
	})

	t.Run("single character", func(t *testing.T) {
		result := ExtractPrintableStrings([]byte{'A'}, 4)
		assert.Empty(t, result, "Should not extract single character")
	})

	t.Run("exactly min length", func(t *testing.T) {
		input := []byte{0x00, 'T', 'e', 's', 't', 0x00}
		result := ExtractPrintableStrings(input, 4)
		resultStr := strings.TrimSpace(string(result))
		assert.Equal(t, "Test", resultStr, "Should extract string exactly at min length")
	})

	t.Run("negative min length", func(t *testing.T) {
		input := []byte{0x00, 'T', 'e', 's', 't', 0x00}
		result := ExtractPrintableStrings(input, -1)
		resultStr := strings.TrimSpace(string(result))
		assert.Equal(t, "Test", resultStr, "Should use default min length for negative values")
	})
}

func TestIsPrintableByte(t *testing.T) {
	tests := []struct {
		name     string
		b        byte
		expected bool
	}{
		{"space", ' ', true},
		{"exclamation", '!', true},
		{"tilde", '~', true},
		{"tab", '\t', true},
		{"newline", '\n', true},
		{"carriage return", '\r', true},
		{"null", 0x00, false},
		{"bell", 0x07, false},
		{"delete", 0x7F, false},
		{"letter A", 'A', true},
		{"digit 5", '5', true},
		{"high byte 0xFF", 0xFF, false},
		{"high byte 0xFE", 0xFE, false},
		{"control character", 0x1F, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPrintableByte(tt.b)
			assert.Equal(t, tt.expected, result, "Printability should match for %s", tt.name)
		})
	}
}

func TestExtractPrintableStrings_MinStringLength(t *testing.T) {
	// Verify the constant value
	assert.Equal(t, 4, MinStringLength, "MinStringLength should be 4 to match Unix strings command")
}

func BenchmarkExtractPrintableStrings(b *testing.B) {
	// Create a realistic test data: 1MB binary with some embedded strings
	data := make([]byte, 1024*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	
	// Embed some strings
	copy(data[1000:], []byte("API_KEY=secret123456"))
	copy(data[50000:], []byte("https://api.example.com"))
	copy(data[500000:], []byte("password=mysupersecretpassword"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ExtractPrintableStrings(data, MinStringLength)
	}
}

func TestExtractPrintableStrings_SecretPatterns(t *testing.T) {
	// Test extraction of various secret patterns that might be found in binaries
	tests := []struct {
		name     string
		input    []byte
		contains string
	}{
		{
			name:     "AWS access key",
			input:    append([]byte{0x00, 0xFF}, []byte("AKIA1234567890ABCDEF")...),
			contains: "AKIA1234567890ABCDEF",
		},
		{
			name:     "GitHub token",
			input:    append([]byte{0x00, 0xFF}, []byte("ghp_1234567890abcdefghijklmnopqrstuv")...),
			contains: "ghp_1234567890abcdefghijklmnopqrstuv",
		},
		{
			name:     "GitLab token",
			input:    append([]byte{0x00, 0xFF}, []byte("glpat-xxxxxxxxxxxxxxxxxxxx")...),
			contains: "glpat-",
		},
		{
			name:     "Private key header",
			input:    append([]byte{0x00, 0xFF}, []byte("-----BEGIN RSA PRIVATE KEY-----")...),
			contains: "BEGIN RSA PRIVATE KEY",
		},
		{
			name:     "Database connection string",
			input:    append([]byte{0x00, 0xFF}, []byte("postgresql://user:pass@localhost/db")...),
			contains: "postgresql://",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractPrintableStrings(tt.input, 4)
			resultStr := string(result)
			assert.Contains(t, resultStr, tt.contains, "Should extract %s from binary", tt.name)
		})
	}
}

func TestExtractPrintableStrings_Reproducibility(t *testing.T) {
	// Ensure the function produces consistent results
	input := []byte{0x00, 0x01, 'T', 'e', 's', 't', 0xFF, 'D', 'a', 't', 'a', 0x00}
	
	result1 := ExtractPrintableStrings(input, 4)
	result2 := ExtractPrintableStrings(input, 4)
	
	require.Equal(t, result1, result2, "Function should produce consistent results")
}
