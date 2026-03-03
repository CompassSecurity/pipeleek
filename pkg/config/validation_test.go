package config

import (
	"strings"
	"testing"
)

func TestValidateURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		url       string
		fieldName string
		wantError bool
		errMsg    string
	}{
		{
			name:      "valid https url",
			url:       "https://gitlab.com",
			fieldName: "GitLab URL",
			wantError: false,
		},
		{
			name:      "valid http url",
			url:       "http://localhost:8080",
			fieldName: "Server URL",
			wantError: false,
		},
		{
			name:      "empty url",
			url:       "",
			fieldName: "API URL",
			wantError: true,
			errMsg:    "cannot be empty",
		},
		{
			name:      "no scheme",
			url:       "gitlab.com",
			fieldName: "GitLab URL",
			wantError: true,
			errMsg:    "must include a scheme",
		},
		{
			name:      "invalid url",
			url:       "ht!tp://invalid",
			fieldName: "URL",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateURL(tt.url, tt.fieldName)
			if tt.wantError {
				if err == nil {
					t.Errorf("ValidateURL() expected error but got none")
				} else if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidateURL() error = %v, want error containing %v", err, tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateURL() unexpected error = %v", err)
				}
			}
		})
	}
}

func TestParseMaxArtifactSize(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		sizeStr   string
		want      int64
		wantError bool
	}{
		{
			name:      "megabytes",
			sizeStr:   "500MB",
			want:      500 * 1000 * 1000, // FromHumanSize uses decimal (1000) not binary (1024)
			wantError: false,
		},
		{
			name:      "gigabytes",
			sizeStr:   "1GB",
			want:      1 * 1000 * 1000 * 1000,
			wantError: false,
		},
		{
			name:      "kilobytes",
			sizeStr:   "100KB",
			want:      100 * 1000,
			wantError: false,
		},
		{
			name:      "invalid format",
			sizeStr:   "invalid",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseMaxArtifactSize(tt.sizeStr)
			if tt.wantError {
				if err == nil {
					t.Errorf("ParseMaxArtifactSize() expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("ParseMaxArtifactSize() unexpected error = %v", err)
				}
				if got != tt.want {
					t.Errorf("ParseMaxArtifactSize() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestValidateToken(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		token     string
		fieldName string
		wantError bool
	}{
		{
			name:      "valid token",
			token:     "glpat-xxxxxxxxxxxxx",
			fieldName: "GitLab Token",
			wantError: false,
		},
		{
			name:      "empty token",
			token:     "",
			fieldName: "API Token",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateToken(tt.token, tt.fieldName)
			if tt.wantError && err == nil {
				t.Errorf("ValidateToken() expected error but got none")
			}
			if !tt.wantError && err != nil {
				t.Errorf("ValidateToken() unexpected error = %v", err)
			}
		})
	}
}

func TestValidateThreadCount(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		threads   int
		wantError bool
	}{
		{
			name:      "valid thread count",
			threads:   4,
			wantError: false,
		},
		{
			name:      "max threads",
			threads:   100,
			wantError: false,
		},
		{
			name:      "min threads",
			threads:   1,
			wantError: false,
		},
		{
			name:      "zero threads",
			threads:   0,
			wantError: true,
		},
		{
			name:      "negative threads",
			threads:   -1,
			wantError: true,
		},
		{
			name:      "too many threads",
			threads:   101,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateThreadCount(tt.threads)
			if tt.wantError && err == nil {
				t.Errorf("ValidateThreadCount() expected error but got none")
			}
			if !tt.wantError && err != nil {
				t.Errorf("ValidateThreadCount() unexpected error = %v", err)
			}
		})
	}
}
