package gitlab

import (
	"testing"

	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/enum"
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/register"
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/shodan"
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/variables"
	"github.com/CompassSecurity/pipeleek/internal/cmd/gitlab/vuln"
)

func TestNewGitLabRootCmd(t *testing.T) {
	cmd := NewGitLabRootCmd()

	if cmd == nil {
		t.Fatal("Expected non-nil command")
		return
	}

	if cmd.Use != "gl [command]" {
		t.Errorf("Expected Use to be 'gl [command]', got %q", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("Expected non-empty Short description")
	}

	if cmd.Long == "" {
		t.Error("Expected non-empty Long description")
	}

	if cmd.GroupID != "GitLab" {
		t.Errorf("Expected GroupID 'GitLab', got %q", cmd.GroupID)
	}

	flags := cmd.PersistentFlags()
	if flags.Lookup("gitlab") == nil {
		t.Error("Expected 'gitlab' persistent flag to exist")
	}
	if flags.Lookup("token") == nil {
		t.Error("Expected 'token' persistent flag to exist")
	}

	if len(cmd.Commands()) < 8 {
		t.Errorf("Expected at least 8 subcommands, got %d", len(cmd.Commands()))
	}
}

func TestNewVulnCmd(t *testing.T) {
	cmd := vuln.NewVulnCmd()

	if cmd == nil {
		t.Fatal("Expected non-nil command")
		return
	}

	if cmd.Use != "vuln" {
		t.Errorf("Expected Use to be 'vuln', got %q", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("Expected non-empty Short description")
	}
}

func TestNewVariablesCmd(t *testing.T) {
	cmd := variables.NewVariablesCmd()

	if cmd == nil {
		t.Fatal("Expected non-nil command")
		return
	}

	if cmd.Use != "variables" {
		t.Errorf("Expected Use to be 'variables', got %q", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("Expected non-empty Short description")
	}

	flags := cmd.Flags()
	if flags.Lookup("gitlab") == nil {
		t.Error("Expected 'gitlab' flag to exist")
	}
}

func TestNewEnumCmd(t *testing.T) {
	cmd := enum.NewEnumCmd()

	if cmd == nil {
		t.Fatal("Expected non-nil command")
		return
	}

	if cmd.Use != "enum" {
		t.Errorf("Expected Use to be 'enum', got %q", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("Expected non-empty Short description")
	}
}

func TestNewRegisterCmd(t *testing.T) {
	cmd := register.NewRegisterCmd()

	if cmd == nil {
		t.Fatal("Expected non-nil command")
		return
	}

	if cmd.Use != "register" {
		t.Errorf("Expected Use to be 'register', got %q", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("Expected non-empty Short description")
	}

	flags := cmd.Flags()
	if flags.Lookup("username") == nil {
		t.Error("Expected 'username' flag to exist")
	}
	if flags.Lookup("email") == nil {
		t.Error("Expected 'email' flag to exist")
	}
	if flags.Lookup("password") == nil {
		t.Error("Expected 'password' flag to exist")
	}
	if flags.Lookup("gitlab") == nil {
		t.Error("Expected 'gitlab' flag to exist")
	}
}

func TestNewShodanCmd(t *testing.T) {
	cmd := shodan.NewShodanCmd()

	if cmd == nil {
		t.Fatal("Expected non-nil command")
		return
	}

	if cmd.Use != "shodan" {
		t.Errorf("Expected Use to be 'shodan', got %q", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("Expected non-empty Short description")
	}

	flags := cmd.Flags()
	if flags.Lookup("shodan-json") == nil {
		t.Error("Expected 'shodan-json' flag to exist")
	}
}
