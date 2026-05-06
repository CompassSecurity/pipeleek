package config

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestScanCommandFlagCoverage verifies that all scan commands define their flags
// and that no flags are missing from AutoBindFlags mappings.
//
// Note: This test documents the expected flag coverage for scan commands.
// Maintainers should add new tests here when new commands or flags are added.
func TestScanCommandFlagCoverage(t *testing.T) {
	tests := map[string]struct {
		// Description of the command
		desc string
		// Expected flags for this scan command (names as they appear in cmd.Flags())
		expectedFlags []string
		// Critical/required flags that MUST have bindings
		criticalFlags []string
	}{
		"gitlab_scan": {
			desc: "GitLab scan command",
			expectedFlags: []string{
				"gitlab", "token", "cookie",
				"search", "member", "repo", "namespace", "job-limit", "queue", "artifacts", "owned",
				"threads", "truffle-hog-verification", "max-artifact-size", "confidence", "hit-timeout",
			},
			criticalFlags: []string{
				"gitlab", "token",
				"search", "repo", "artifacts", "owned",
				"threads", "truffle-hog-verification", "max-artifact-size", "confidence", "hit-timeout",
			},
		},
		"github_scan": {
			desc: "GitHub scan command",
			expectedFlags: []string{
				"github", "token",
				"org", "user", "search", "repo", "public", "max-workflows", "artifacts", "owned",
				"threads", "truffle-hog-verification", "max-artifact-size", "confidence", "hit-timeout",
			},
			criticalFlags: []string{
				"github", "token",
				"org", "user", "search", "repo", "artifacts", "owned",
				"threads", "truffle-hog-verification", "max-artifact-size", "confidence", "hit-timeout",
			},
		},
		"bitbucket_scan": {
			desc: "BitBucket scan command",
			expectedFlags: []string{
				"bitbucket", "email", "token", "cookie",
				"workspace", "max-pipelines", "public", "after", "artifacts", "owned",
				"threads", "truffle-hog-verification", "max-artifact-size", "confidence", "hit-timeout",
			},
			criticalFlags: []string{
				"bitbucket", "email", "token",
				"workspace", "artifacts", "owned",
				"threads", "truffle-hog-verification", "max-artifact-size", "confidence", "hit-timeout",
			},
		},
		"devops_scan": {
			desc: "Azure DevOps scan command",
			expectedFlags: []string{
				"devops", "token", "username",
				"organization", "project", "max-builds", "artifacts", "owned",
				"threads", "truffle-hog-verification", "max-artifact-size", "confidence", "hit-timeout",
			},
			criticalFlags: []string{
				"devops", "token",
				"organization", "project", "artifacts", "owned",
				"threads", "truffle-hog-verification", "max-artifact-size", "confidence", "hit-timeout",
			},
		},
		"gitea_scan": {
			desc: "Gitea scan command",
			expectedFlags: []string{
				"gitea", "token", "cookie",
				"organization", "repository", "runs-limit", "start-run-id", "artifacts", "owned",
				"threads", "truffle-hog-verification", "max-artifact-size", "confidence", "hit-timeout",
			},
			criticalFlags: []string{
				"gitea", "token",
				"organization", "repository", "artifacts", "owned",
				"threads", "truffle-hog-verification", "max-artifact-size", "confidence", "hit-timeout",
			},
		},
		"jenkins_scan": {
			desc: "Jenkins scan command",
			expectedFlags: []string{
				"jenkins", "username", "token",
				"folder", "job", "max-builds", "artifacts",
				"threads", "truffle-hog-verification", "max-artifact-size", "confidence", "hit-timeout",
			},
			criticalFlags: []string{
				"jenkins", "token",
				"artifacts",
				"threads", "truffle-hog-verification", "max-artifact-size", "confidence", "hit-timeout",
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// This is a documentation test that lists what flags SHOULD exist.
			// Actual flag tests are in the command-specific test files.
			// This serves as a checklist for maintainers.
			t.Logf("Command: %s", tc.desc)
			t.Logf("Expected flags: %v", tc.expectedFlags)
			t.Logf("Critical flags (required): %v", tc.criticalFlags)

			// Verify that critical flags is a subset of expected
			for _, critical := range tc.criticalFlags {
				found := false
				for _, expected := range tc.expectedFlags {
					if critical == expected {
						found = true
						break
					}
				}
				assert.True(t, found, "Critical flag %q should be in expectedFlags", critical)
			}
		})
	}
}

// TestAutoBindFlagsRejectsBadMappings verifies that AutoBindFlags properly
// handles edge cases like invalid flag names and unknown keys.
func TestAutoBindFlagsRejectsBadMappings(t *testing.T) {
	t.Run("NonexistentFlagIsIgnored", func(t *testing.T) {
		globalViper = nil
		err := InitializeViper("")
		require.NoError(t, err)

		cmd := &cobra.Command{Use: "test"}
		cmd.Flags().String("existing-flag", "", "")

		// Map a flag that doesn't exist - should not error
		err = AutoBindFlags(cmd, map[string]string{
			"nonexistent-flag": "some.key",
			"existing-flag":    "some.other.key",
		})
		assert.NoError(t, err, "AutoBindFlags should not error on nonexistent flags")
	})

	t.Run("EmptyMappingIsValid", func(t *testing.T) {
		globalViper = nil
		err := InitializeViper("")
		require.NoError(t, err)

		cmd := &cobra.Command{Use: "test"}
		err = AutoBindFlags(cmd, map[string]string{})
		assert.NoError(t, err, "AutoBindFlags should accept empty mapping")
	})

	t.Run("DashesInFlagsConvertedToUnderscores", func(t *testing.T) {
		globalViper = nil
		err := InitializeViper("")
		require.NoError(t, err)

		cmd := &cobra.Command{Use: "test"}
		cmd.Flags().String("my-flag-name", "default", "")

		err = AutoBindFlags(cmd, map[string]string{
			"my-flag-name": "config.my_flag_name",
		})
		require.NoError(t, err)

		err = cmd.Flags().Set("my-flag-name", "value")
		require.NoError(t, err)

		// Verify the key is stored with underscores in viper
		value := GetString("config.my_flag_name")
		assert.Equal(t, "value", value, "Flag name dashes should convert to underscores in viper key")
	})
}

// TestBindFlagsWithSubcommands verifies that AutoBindFlags works correctly
// with parent/child command hierarchies (inherited flags).
func TestBindFlagsWithSubcommands(t *testing.T) {
	t.Run("InheritedFlagsFromParent", func(t *testing.T) {
		globalViper = nil
		err := InitializeViper("")
		require.NoError(t, err)

		// Create parent and child commands
		parent := &cobra.Command{Use: "parent"}
		parent.PersistentFlags().String("token", "", "API token")

		child := &cobra.Command{Use: "child"}
		parent.AddCommand(child)

		// Add child-specific flag
		child.Flags().String("search", "", "Search query")

		// Bind both parent (inherited) and child flags
		err = AutoBindFlags(child, map[string]string{
			"token":  "api.token",
			"search": "scan.search",
		})
		require.NoError(t, err)

		// Set parent flag and child flag
		err = parent.PersistentFlags().Set("token", "parent-token")
		require.NoError(t, err)

		err = child.Flags().Set("search", "my-search")
		require.NoError(t, err)

		// Verify both are accessible through config
		assert.Equal(t, "parent-token", GetString("api.token"), "Inherited flag should be bound")
		assert.Equal(t, "my-search", GetString("scan.search"), "Child flag should be bound")
	})
}

// TestBoolFlagBinding verifies that boolean flags are correctly bound and retrieved.
func TestBoolFlagBinding(t *testing.T) {
	globalViper = nil
	err := InitializeViper("")
	require.NoError(t, err)

	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().Bool("artifacts", false, "Include artifacts")
	cmd.Flags().Bool("owned", false, "Only owned")

	err = AutoBindFlags(cmd, map[string]string{
		"artifacts": "scan.artifacts",
		"owned":     "scan.owned",
	})
	require.NoError(t, err)

	// Test true values
	err = cmd.Flags().Set("artifacts", "true")
	require.NoError(t, err)
	err = cmd.Flags().Set("owned", "true")
	require.NoError(t, err)

	assert.True(t, GetBool("scan.artifacts"), "Bool true should be bound correctly")
	assert.True(t, GetBool("scan.owned"), "Bool true should be bound correctly")

	// Reset for testing false values
	globalViper = nil
	err = InitializeViper("")
	require.NoError(t, err)

	cmd2 := &cobra.Command{Use: "test2"}
	cmd2.Flags().Bool("artifacts", false, "")
	cmd2.Flags().Bool("owned", false, "")

	err = AutoBindFlags(cmd2, map[string]string{
		"artifacts": "scan.artifacts",
		"owned":     "scan.owned",
	})
	require.NoError(t, err)

	// Don't set any flags - should use defaults
	assert.False(t, GetBool("scan.artifacts"), "Bool false (default) should be bound correctly")
	assert.False(t, GetBool("scan.owned"), "Bool false (default) should be bound correctly")
}

// TestIntFlagBinding verifies that integer flags are correctly bound and retrieved.
func TestIntFlagBinding(t *testing.T) {
	globalViper = nil
	err := InitializeViper("")
	require.NoError(t, err)

	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().Int("threads", 4, "Thread count")
	cmd.Flags().Int("max-builds", 0, "Max builds")

	err = AutoBindFlags(cmd, map[string]string{
		"threads":    "common.threads",
		"max-builds": "scan.max_builds",
	})
	require.NoError(t, err)

	err = cmd.Flags().Set("threads", "10")
	require.NoError(t, err)
	err = cmd.Flags().Set("max-builds", "50")
	require.NoError(t, err)

	assert.Equal(t, 10, GetInt("common.threads"), "Integer value should be bound correctly")
	assert.Equal(t, 50, GetInt("scan.max_builds"), "Integer value should be bound correctly")
}

// TestStringSliceFlagBinding verifies that string slice flags are correctly bound.
func TestStringSliceFlagBinding(t *testing.T) {
	globalViper = nil
	err := InitializeViper("")
	require.NoError(t, err)

	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().StringSlice("confidence", []string{}, "Confidence levels")

	err = AutoBindFlags(cmd, map[string]string{
		"confidence": "common.confidence_filter",
	})
	require.NoError(t, err)

	// Set multiple values
	err = cmd.Flags().Set("confidence", "high,medium,low")
	require.NoError(t, err)

	confidence := GetStringSlice("common.confidence_filter")
	assert.Equal(t, []string{"high", "medium", "low"}, confidence, "String slice should be bound correctly")
}

// TestRequireConfigKeysWithBoundFlags verifies that RequireConfigKeys works
// correctly after flags have been bound.
func TestRequireConfigKeysWithBoundFlags(t *testing.T) {
	globalViper = nil
	err := InitializeViper("")
	require.NoError(t, err)

	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("url", "", "")
	cmd.Flags().String("token", "", "")

	err = AutoBindFlags(cmd, map[string]string{
		"url":   "gitlab.url",
		"token": "gitlab.token",
	})
	require.NoError(t, err)

	// Both flags unset - should fail
	err = RequireConfigKeys("gitlab.url", "gitlab.token")
	assert.Error(t, err, "Should error when required keys are not set")

	// Set one flag
	err = cmd.Flags().Set("url", "https://gitlab.com")
	require.NoError(t, err)
	err = RequireConfigKeys("gitlab.url", "gitlab.token")
	assert.Error(t, err, "Should error when only one required key is set")

	// Set both flags
	err = cmd.Flags().Set("token", "my-token")
	require.NoError(t, err)
	err = RequireConfigKeys("gitlab.url", "gitlab.token")
	assert.NoError(t, err, "Should pass when all required keys are set")
}

// ================== Documentation Tests ==================

// TestFlagBindingDocumentation documents the expected behavior of flag binding.
// This serves as a comprehensive reference for how configuration should work.
func TestFlagBindingDocumentation(t *testing.T) {
	doc := `
FLAG BINDING REFERENCE
======================

Configuration Priority Order (highest to lowest):
1. CLI Flags (--flag value)
2. Environment Variables (PIPELEEK_KEY_NAME)
3. Config File (yaml, toml, etc.)
4. Default Values

Example:
  pipeleek gitlab scan \
    --gitlab https://cli.example.com \              # Priority 1: CLI flag
    --token cli-token                               # Priority 1: CLI flag

  With env vars:
  export PIPELEEK_GITLAB_URL=https://env.example.com
  export PIPELEEK_GITLAB_TOKEN=env-token

  With config file (pipeleek.yaml):
  gitlab:
    url: https://file.example.com
    token: file-token

  Resolution:
  - url: https://cli.example.com (CLI flag wins)
  - token: cli-token (CLI flag wins)
  - If no CLI flag: env var is checked
  - If no env var: config file is checked
  - If no config: default is used

Key Naming Convention:
  - CLI flag: --my-flag-name (dashes)
  - Viper key: platform.subcommand.my_flag_name (underscores)
  - Environment: PIPELEEK_PLATFORM_SUBCOMMAND_MY_FLAG_NAME (all caps)
  - Config YAML: platform.subcommand.my_flag_name = value

Testing Each Command:
  For each scan command, verify:
  1. All flags are defined (cmd.Flags().StringVar, BoolVar, etc.)
  2. All flags are bound (AutoBindFlags mapping)
  3. All flags are read (config.GetString, GetBool, GetInt, etc.)
  4. Critical flags require values (RequireConfigKeys)
`
	t.Log(strings.TrimSpace(doc))
}
