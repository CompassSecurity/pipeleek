package scan

import (
	"os"
	"strings"
	"testing"

	"github.com/CompassSecurity/pipeleek/internal/cmd/testutil"
	"github.com/CompassSecurity/pipeleek/pkg/config"
	"github.com/CompassSecurity/pipeleek/pkg/config/gen"
	"github.com/CompassSecurity/pipeleek/pkg/gitlab/scan"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gitlab "gitlab.com/gitlab-org/api/client-go"
	"gopkg.in/yaml.v3"
)

func TestGitLabScan_AllDefinedFlagsAreBound(t *testing.T) {
	cmd := NewScanCmd()
	testutil.AssertAllFlagsHaveBindings(t, cmd, flagBindings, "url", "token")
}

func TestNewScanCmd(t *testing.T) {
	cmd := NewScanCmd()
	if cmd == nil {
		t.Fatal("Expected non-nil command")
	}

	if cmd.Use != "scan" {
		t.Errorf("Expected Use to be 'scan', got %q", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("Expected non-empty Short description")
	}

	if cmd.Example == "" {
		t.Error("Expected non-empty Example")
	}

	flags := cmd.Flags()
	for _, name := range []string{
		"cookie",
		"search",
		"member",
		"repo",
		"namespace",
		"job-limit",
		"job-status",
		"queue",
		"artifacts",
		"owned",
		"threads",
		"secrets-verification",
		"max-artifact-size",
		"confidence",
		"hit-timeout",
	} {
		if flags.Lookup(name) == nil {
			t.Errorf("Expected flag %q to exist", name)
		}
	}
}

func TestJobStatusConfig(t *testing.T) {
	tests := []struct {
		name  string
		yaml  string
		env   string
		flags []string
		want  []gitlab.BuildStateValue
	}{
		{name: "default"},
		{name: "config", yaml: "gitlab:\n  scan:\n    job_status: [success, failed]\n", want: []gitlab.BuildStateValue{gitlab.Success, gitlab.Failed}},
		{name: "environment", env: "success,failed", want: []gitlab.BuildStateValue{gitlab.Success, gitlab.Failed}},
		{name: "comma separated flag", flags: []string{"--job-status", "success,failed"}, want: []gitlab.BuildStateValue{gitlab.Success, gitlab.Failed}},
		{name: "repeated flag", flags: []string{"--job-status", "success", "--job-status", "failed"}, want: []gitlab.BuildStateValue{gitlab.Success, gitlab.Failed}},
		{name: "flag overrides environment and config", yaml: "gitlab:\n  scan:\n    job_status: [running]\n", env: "failed", flags: []string{"--job-status", "success"}, want: []gitlab.BuildStateValue{gitlab.Success}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("PIPELEEK_NO_CONFIG", "1")
			t.Setenv("PIPELEEK_GITLAB_SCAN_JOB_STATUS", tt.env)
			require.NoError(t, config.InitializeViper(""))
			if tt.yaml != "" {
				config.GetViper().SetConfigType("yaml")
				require.NoError(t, config.GetViper().ReadConfig(strings.NewReader(tt.yaml)))
			}
			cmd := NewScanCmd()
			require.NoError(t, cmd.ParseFlags(tt.flags))
			require.NoError(t, config.NewCommandSetup(cmd).WithFlagBindings(flagBindings).Bind())
			got, err := scan.ParseJobStatuses(config.GetStringSlice("gitlab.scan.job_status"))
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestJobStatusGeneratedConfig(t *testing.T) {
	root := &cobra.Command{Use: "pipeleek"}
	gl := &cobra.Command{Use: "gl"}
	gl.AddCommand(NewScanCmd())
	root.AddCommand(gl)
	content := gen.GenerateExampleConfig(root)
	assert.Contains(t, content, "PIPELEEK_GITLAB_SCAN_JOB_STATUS")
	var generated struct {
		GitLab struct {
			Scan struct {
				JobStatus []string `yaml:"job_status"`
			} `yaml:"scan"`
		} `yaml:"gitlab"`
	}
	require.NoError(t, yaml.Unmarshal([]byte(content), &generated))
	assert.NotNil(t, generated.GitLab.Scan.JobStatus)
	assert.Empty(t, generated.GitLab.Scan.JobStatus)
}

func TestNewScanCmdFlagsAreIndependent(t *testing.T) {
	first := NewScanCmd()
	require.NoError(t, first.ParseFlags([]string{"--artifacts", "--owned", "--job-status", "failed"}))
	second := NewScanCmd()
	assert.Equal(t, "true", first.Flags().Lookup("artifacts").Value.String())
	assert.Equal(t, "true", first.Flags().Lookup("owned").Value.String())
	assert.Equal(t, "[failed]", first.Flags().Lookup("job-status").Value.String())
	assert.Equal(t, "false", second.Flags().Lookup("artifacts").Value.String())
	assert.Equal(t, "[]", second.Flags().Lookup("job-status").Value.String())
}
func TestGitLabScanFlagBindings(t *testing.T) {
	t.Setenv("PIPELEEK_NO_CONFIG", "1")

	if err := config.InitializeViper(""); err != nil {
		t.Fatalf("InitializeViper failed: %v", err)
	}

	cmd := NewScanCmd()

	// Set flag values
	flagMap := map[string]string{
		"search":    "mysearch",
		"repo":      "group/myrepo",
		"namespace": "mygroup",
		"queue":     "/tmp/queue",
	}
	for flag, value := range flagMap {
		if err := cmd.Flags().Set(flag, value); err != nil {
			t.Fatalf("Failed to set flag %q: %v", flag, err)
		}
	}
	if err := cmd.Flags().Set("artifacts", "true"); err != nil {
		t.Fatalf("Failed to set artifacts flag: %v", err)
	}
	if err := cmd.Flags().Set("owned", "true"); err != nil {
		t.Fatalf("Failed to set owned flag: %v", err)
	}
	if err := cmd.Flags().Set("member", "true"); err != nil {
		t.Fatalf("Failed to set member flag: %v", err)
	}

	// Bind flags to Viper keys (same mapping as in Scan())
	if err := config.NewCommandSetup(cmd).WithFlagBindings(flagBindings).Bind(); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	// Verify flag values are accessible via Viper keys
	if got := config.GetString("gitlab.scan.search"); got != "mysearch" {
		t.Errorf("Expected gitlab.scan.search=%q, got %q", "mysearch", got)
	}
	if got := config.GetString("gitlab.scan.repo"); got != "group/myrepo" {
		t.Errorf("Expected gitlab.scan.repo=%q, got %q", "group/myrepo", got)
	}
	if got := config.GetString("gitlab.scan.namespace"); got != "mygroup" {
		t.Errorf("Expected gitlab.scan.namespace=%q, got %q", "mygroup", got)
	}
	if got := config.GetString("gitlab.scan.queue"); got != "/tmp/queue" {
		t.Errorf("Expected gitlab.scan.queue=%q, got %q", "/tmp/queue", got)
	}
	if got := config.GetBool("gitlab.scan.artifacts"); !got {
		t.Error("Expected gitlab.scan.artifacts=true")
	}
	if got := config.GetBool("gitlab.scan.owned"); !got {
		t.Error("Expected gitlab.scan.owned=true")
	}
	if got := config.GetBool("gitlab.scan.member"); !got {
		t.Error("Expected gitlab.scan.member=true")
	}
}

func TestGitLabScanEnvVarBinding(t *testing.T) {
	t.Setenv("PIPELEEK_NO_CONFIG", "1")
	t.Setenv("PIPELEEK_GITLAB_SCAN_SEARCH", "env-search")
	t.Setenv("PIPELEEK_GITLAB_SCAN_ARTIFACTS", "true")

	if err := config.InitializeViper(""); err != nil {
		t.Fatalf("InitializeViper failed: %v", err)
	}

	cmd := NewScanCmd()

	if err := config.NewCommandSetup(cmd).WithFlagBindings(flagBindings).Bind(); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	// Verify env vars are read (flag not set, so env var should win)
	if got := config.GetString("gitlab.scan.search"); got != "env-search" {
		t.Errorf("Expected gitlab.scan.search=%q from env var, got %q", "env-search", got)
	}
	if got := config.GetBool("gitlab.scan.artifacts"); !got {
		t.Errorf("Expected gitlab.scan.artifacts=true from env var, got %v", got)
	}

	os.Unsetenv("PIPELEEK_GITLAB_SCAN_SEARCH")
	os.Unsetenv("PIPELEEK_GITLAB_SCAN_ARTIFACTS")
}
