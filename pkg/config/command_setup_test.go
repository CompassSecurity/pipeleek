package config

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestCommandSetup_WithFlagBindings(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}

	setup := NewCommandSetup(cmd).
		WithFlagBindings(map[string]string{
			"token": "gitlab.token",
			"url":   "gitlab.url",
		}).
		RequireKeys("gitlab.token", "gitlab.url")

	assert.NotNil(t, setup)
	assert.Equal(t, len(setup.flagBindings), 2)
	assert.Equal(t, len(setup.requiredKeys), 2)
}

func TestCommandSetup_AddValidator(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}

	validatorCalled := false
	setup := NewCommandSetup(cmd).
		AddValidator(func() error {
			validatorCalled = true
			return nil
		})

	err := setup.Bind()
	assert.NoError(t, err)
	assert.True(t, validatorCalled)
}

func TestBindingsFromFlags(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("token", "", "A token")
	cmd.Flags().String("max-artifact-size", "", "Max size")

	bindings := BindingsFromFlags(cmd, "gitlab", "scan", map[string]string{})

	assert.Equal(t, bindings["token"], "gitlab.scan.token")
	assert.Equal(t, bindings["max-artifact-size"], "gitlab.scan.max_artifact_size")
}

func TestBindingsFromFlags_WithOverrides(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("token", "", "A token")
	cmd.Flags().String("threads", "", "Thread count")

	bindings := BindingsFromFlags(cmd, "gitlab", "scan", map[string]string{
		"threads": "common.threads", // Override the standard derivation
	})

	assert.Equal(t, bindings["token"], "gitlab.scan.token")
	assert.Equal(t, bindings["threads"], "common.threads")
}
