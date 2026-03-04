package format

import (
	"runtime"
	"testing"
)

func TestContainsI(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		a        string
		b        string
		expected bool
	}{
		{
			name:     "exact match",
			a:        "hello",
			b:        "hello",
			expected: true,
		},
		{
			name:     "case insensitive match",
			a:        "Hello World",
			b:        "world",
			expected: true,
		},
		{
			name:     "uppercase in both",
			a:        "HELLO WORLD",
			b:        "WORLD",
			expected: true,
		},
		{
			name:     "mixed case",
			a:        "HeLLo WoRLd",
			b:        "llo wo",
			expected: true,
		},
		{
			name:     "no match",
			a:        "hello",
			b:        "goodbye",
			expected: false,
		},
		{
			name:     "empty substring",
			a:        "hello",
			b:        "",
			expected: true,
		},
		{
			name:     "empty string",
			a:        "",
			b:        "hello",
			expected: false,
		},
		{
			name:     "both empty",
			a:        "",
			b:        "",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := ContainsI(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("ContainsI(%q, %q) = %v, want %v", tt.a, tt.b, result, tt.expected)
			}
		})
	}
}

func TestGetPlatformAgnosticNewline(t *testing.T) {
	t.Parallel()
	result := GetPlatformAgnosticNewline()

	if runtime.GOOS == "windows" {
		if result != "\r\n" {
			t.Errorf("GetPlatformAgnosticNewline() on Windows = %q, want %q", result, "\r\n")
		}
	} else {
		if result != "\n" {
			t.Errorf("GetPlatformAgnosticNewline() on Unix = %q, want %q", result, "\n")
		}
	}
}

func TestRandomStringN(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		length int
	}{
		{name: "length 0", length: 0},
		{name: "length 1", length: 1},
		{name: "length 10", length: 10},
		{name: "length 100", length: 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RandomStringN(tt.length)
			if len(result) != tt.length {
				t.Errorf("RandomStringN(%d) returned string of length %d, want %d", tt.length, len(result), tt.length)
			}

			for _, c := range result {
				if c < 'a' || c > 'z' {
					t.Errorf("RandomStringN(%d) returned string with non-lowercase character: %c", tt.length, c)
				}
			}
		})
	}

	t.Run("randomness check", func(t *testing.T) {
		s1 := RandomStringN(20)
		s2 := RandomStringN(20)
		if s1 == s2 {
			t.Log("Warning: Two random strings were identical, but this could happen rarely")
		}
	})
}
