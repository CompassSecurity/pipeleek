package circle

import "testing"

func TestNewCircleRootCmd(t *testing.T) {
	cmd := NewCircleRootCmd()
	if cmd == nil {
		t.Fatal("Expected non-nil command")
	}

	if cmd.Use != "circle [command]" {
		t.Errorf("Expected Use to be 'circle [command]', got %q", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("Expected non-empty Short description")
	}

	if cmd.GroupID != "CircleCI" {
		t.Errorf("Expected GroupID 'CircleCI', got %q", cmd.GroupID)
	}

	if len(cmd.Commands()) != 1 {
		t.Errorf("Expected 1 subcommand, got %d", len(cmd.Commands()))
	}

	if len(cmd.Commands()) == 1 && cmd.Commands()[0].Use != "scan" {
		t.Errorf("Expected subcommand 'scan', got %q", cmd.Commands()[0].Use)
	}
}
