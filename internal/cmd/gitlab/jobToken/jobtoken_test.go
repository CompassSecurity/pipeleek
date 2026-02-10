package jobtoken

import "testing"

func TestNewJobTokenRootCmd(t *testing.T) {
	cmd := NewJobTokenRootCmd()
	if cmd == nil {
		t.Fatal("expected non-nil command")
	}

	if cmd.Use != "jobToken" {
		t.Fatalf("expected Use to be jobToken, got %q", cmd.Use)
	}

	if cmd.Short == "" {
		t.Fatal("expected non-empty Short description")
	}

	if cmd.Long == "" {
		t.Fatal("expected non-empty Long description")
	}

	flags := cmd.PersistentFlags()
	if flags.Lookup("gitlab") == nil {
		t.Fatal("expected gitlab flag to exist")
	}
	if flags.Lookup("token") == nil {
		t.Fatal("expected token flag to exist")
	}

	foundExploit := false
	for _, sub := range cmd.Commands() {
		if sub.Use == "exploit" {
			foundExploit = true
			break
		}
	}
	if !foundExploit {
		t.Fatal("expected exploit subcommand to be registered")
	}
}
