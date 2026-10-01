package config

import "testing"

func TestDefaultCommonScanOptions(t *testing.T) {
	opts := DefaultCommonScanOptions()

	if opts.MaxScanGoRoutines != 4 {
		t.Errorf("Expected MaxScanGoRoutines to be 4, got %d", opts.MaxScanGoRoutines)
	}

	if !opts.SecretsVerification {
		t.Error("Expected SecretsVerification to be true")
	}

	if opts.Artifacts {
		t.Error("Expected Artifacts to be false by default")
	}

	expectedSize := int64(500 * 1024 * 1024)
	if opts.MaxArtifactSize != expectedSize {
		t.Errorf("Expected MaxArtifactSize to be %d, got %d", expectedSize, opts.MaxArtifactSize)
	}

	if opts.Owned {
		t.Error("Expected Owned to be false by default")
	}

	if len(opts.ConfidenceFilter) != 0 {
		t.Error("Expected ConfidenceFilter to be empty by default")
	}
}
