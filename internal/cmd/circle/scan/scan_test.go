package scan

import "testing"

func TestNewScanCmd(t *testing.T) {
	cmd := NewScanCmd()
	if cmd == nil {
		t.Fatal("expected non-nil command")
	}

	if cmd.Use != "scan" {
		t.Fatalf("expected use 'scan', got %q", cmd.Use)
	}

	flags := cmd.Flags()
	for _, name := range []string{
		"token",
		"circle",
		"org",
		"project",
		"vcs",
		"branch",
		"status",
		"workflow",
		"job",
		"since",
		"until",
		"max-pipelines",
		"tests",
		"insights",
		"threads",
		"truffle-hog-verification",
		"confidence",
		"artifacts",
		"max-artifact-size",
	} {
		if flags.Lookup(name) == nil {
			t.Errorf("expected flag %q to exist", name)
		}
	}
}
