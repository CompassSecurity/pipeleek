package ghtoken

import (
	"testing"

	"github.com/spf13/pflag"
)

func TestNewGhTokenRootCmd(t *testing.T) {
	cmd := NewGhTokenRootCmd()
	if cmd == nil {
		t.Fatal("expected non-nil command")
	}

	if cmd.Use != "ghtoken" {
		t.Fatalf("expected Use to be ghtoken, got %q", cmd.Use)
	}

	if cmd.Short == "" {
		t.Fatal("expected non-empty Short description")
	}

	if cmd.Long == "" {
		t.Fatal("expected non-empty Long description")
	}

	flags := cmd.PersistentFlags()
	if flags.Lookup("github") == nil {
		t.Fatal("expected github flag to exist")
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

func TestGhTokenCmd_AllDefinedFlagsAreBound(t *testing.T) {
cmd := NewGhTokenRootCmd()
cmd.PersistentFlags().VisitAll(func(flag *pflag.Flag) {
if flag.Name == "help" {
return
}
if _, ok := flagBindings[flag.Name]; !ok {
t.Errorf("persistent flag %q is defined but missing from flagBindings", flag.Name)
}
})
}
