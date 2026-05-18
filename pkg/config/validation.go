package config

import (
	"fmt"
	"net/url"

	"github.com/docker/go-units"
)

// ValidateURL validates that a string is a valid URL.
func ValidateURL(urlStr string, fieldName string) error {
	if urlStr == "" {
		return fmt.Errorf("%s cannot be empty", fieldName)
	}

	parsed, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("invalid %s: %w", fieldName, err)
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("%s must use http or https scheme, got %q", fieldName, parsed.Scheme)
	}

	if parsed.Host == "" {
		return fmt.Errorf("%s must include a host", fieldName)
	}

	return nil
}

// ParseMaxArtifactSize parses a human-readable size string (e.g., "500MB", "1GB") into bytes.
func ParseMaxArtifactSize(sizeStr string) (int64, error) {
	size, err := units.FromHumanSize(sizeStr)
	if err != nil {
		return 0, fmt.Errorf("failed to parse max artifact size: %w", err)
	}
	return size, nil
}

// ValidateToken validates that a token is not empty.
func ValidateToken(token string, fieldName string) error {
	if token == "" {
		return fmt.Errorf("%s cannot be empty", fieldName)
	}
	return nil
}

// ValidateThreadCount validates that the thread count is within acceptable bounds.
func ValidateThreadCount(threads int) error {
	if threads < 1 {
		return fmt.Errorf("thread count must be at least 1, got %d", threads)
	}
	if threads > 100 {
		return fmt.Errorf("thread count too high (max 100), got %d", threads)
	}
	return nil
}
