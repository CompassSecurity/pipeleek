// Package config provides shared configuration types and validation helpers for pipeleek.
// This package centralizes common configuration patterns across all platform scanners.
package config

import "time"

// CommonScanOptions contains configuration fields that are shared across all platform scanners.
// This helps reduce duplication and ensures consistency in option handling.
type CommonScanOptions struct {
	// ConfidenceFilter filters results by confidence level
	ConfidenceFilter []string
	// MaxScanGoRoutines controls the number of concurrent scanning threads
	MaxScanGoRoutines int
	// SecretsVerification enables or disables provider verification for supported credentials.
	SecretsVerification bool
	// Artifacts enables/disables artifact scanning
	Artifacts bool
	// WebUI starts a local web UI with live findings for scan runs.
	WebUI bool
	// MaxArtifactSize is the maximum size of artifacts to scan (in bytes)
	MaxArtifactSize int64
	// Owned filters to only owned repositories
	Owned bool
	// HitTimeout is the maximum time to wait for hit detection per scan item
	HitTimeout time.Duration
}

// DefaultCommonScanOptions returns sensible default values for common scan options.
func DefaultCommonScanOptions() CommonScanOptions {
	return CommonScanOptions{
		ConfidenceFilter:    []string{},
		MaxScanGoRoutines:   4,
		SecretsVerification: true,
		Artifacts:           false,
		WebUI:               false,
		MaxArtifactSize:     500 * 1024 * 1024, // 500MB
		Owned:               false,
		HitTimeout:          60 * time.Second,
	}
}
