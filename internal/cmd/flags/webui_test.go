package flags

import (
	"reflect"
	"testing"
	"time"

	"github.com/CompassSecurity/pipeleek/pkg/config"
	"github.com/spf13/cobra"
)

func TestScanContextFromCommandUsesBoundValuesAndIncludesLocalFlags(t *testing.T) {
	t.Setenv("PIPELEEK_NO_CONFIG", "1")
	config.ResetViper()
	t.Cleanup(config.ResetViper)
	v := config.GetViper()

	cmd := &cobra.Command{Use: "scan"}
	cmd.Flags().String("url", "https://example.test", "")
	cmd.Flags().String("token", "", "")
	cmd.Flags().String("cookie", "", "")
	cmd.Flags().Int("threads", 4, "")
	cmd.Flags().String("repository", "", "")
	cmd.Flags().Bool("secrets-verification", true, "")
	cmd.Flags().Bool("artifacts", false, "")
	cmd.Flags().Int("max-builds", 0, "")
	cmd.Flags().Duration("hit-timeout", time.Minute, "")
	cmd.Flags().String("branch", "", "")
	cmd.Flags().String("search", "", "")
	cmd.Flags().String("job", "", "")
	cmd.Flags().Bool("webui", false, "")
	cmd.Flags().String("unset-option", "", "")
	cmd.Flags().String("local-filter", "default", "")

	bindings := map[string]string{
		"url":                  "gitea.url",
		"token":                "gitea.token",
		"cookie":               "gitea.cookie",
		"threads":              "common.threads",
		"repository":           "gitea.scan.repository",
		"secrets-verification": "common.secrets_verification",
		"artifacts":            "gitea.scan.artifacts",
		"max-builds":           "gitea.scan.max_builds",
		"hit-timeout":          "common.hit_timeout",
		"branch":               "gitea.scan.branch",
		"search":               "gitea.scan.search",
		"job":                  "gitea.scan.job",
		"webui":                "common.webui",
	}
	for name, key := range bindings {
		if flag := cmd.Flags().Lookup(name); flag != nil {
			if err := v.BindPFlag(key, flag); err != nil {
				t.Fatal(err)
			}
		}
	}
	v.Set("gitea.token", "config-token")
	v.Set("gitea.cookie", "config-cookie")
	v.Set("common.threads", 8)
	v.Set("gitea.scan.repository", "owner/project")
	v.Set("common.secrets_verification", true)
	v.Set("gitea.scan.artifacts", false)
	v.Set("gitea.scan.max_builds", 0)
	v.Set("common.hit_timeout", "0s")
	v.Set("gitea.scan.branch", "false")
	v.Set("gitea.scan.search", "0")
	v.Set("gitea.scan.job", "1m")
	if err := cmd.Flags().Set("local-filter", "selected"); err != nil {
		t.Fatal(err)
	}

	got := scanContextFromCommand(cmd, "https://example.test", bindings)
	names := make([]string, len(got.Options))
	values := make(map[string]string, len(got.Options))
	for i, option := range got.Options {
		names[i] = option.Name
		values[option.Name] = option.Value
	}

	wantNames := []string{
		"--branch",
		"--cookie",
		"--job",
		"--local-filter",
		"--repository",
		"--search",
		"--secrets-verification",
		"--threads",
		"--token",
	}
	if !reflect.DeepEqual(names, wantNames) {
		t.Fatalf("option names = %v, want %v", names, wantNames)
	}
	wantValues := map[string]string{
		"--cookie":               "config-cookie",
		"--branch":               "false",
		"--job":                  "1m",
		"--local-filter":         "selected",
		"--repository":           "owner/project",
		"--search":               "0",
		"--secrets-verification": "true",
		"--threads":              "8",
		"--token":                "config-token",
	}
	if !reflect.DeepEqual(values, wantValues) {
		t.Fatalf("option values = %v, want %v", values, wantValues)
	}
}

func TestIsEnabledScanFlag(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().Bool("enabled-bool", false, "")
	cmd.Flags().Int("enabled-int", 0, "")
	cmd.Flags().String("string", "", "")
	cmd.Flags().Duration("duration", 0, "")
	tests := []struct {
		name     string
		flagName string
		value    interface{}
		want     bool
	}{
		{name: "true boolean", flagName: "enabled-bool", value: true, want: true},
		{name: "false boolean", flagName: "enabled-bool", value: false},
		{name: "zero integer", flagName: "enabled-int", value: 0},
		{name: "positive integer", flagName: "enabled-int", value: 4, want: true},
		{name: "non-empty string", flagName: "string", value: "selected", want: true},
		{name: "false string is enabled", flagName: "string", value: "false", want: true},
		{name: "zero string is enabled", flagName: "string", value: "0", want: true},
		{name: "duration-looking string is enabled", flagName: "string", value: "1m", want: true},
		{name: "empty string", flagName: "string", value: ""},
		{name: "zero duration", flagName: "duration", value: time.Duration(0)},
		{name: "positive duration", flagName: "duration", value: time.Minute, want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			flag := cmd.Flags().Lookup(test.flagName)
			if got := isEnabledScanFlag(flag, test.value); got != test.want {
				t.Fatalf("isEnabledScanFlag(%#v) = %t, want %t", test.value, got, test.want)
			}
		})
	}
}

func TestScanContextOmitsUnboundInheritedFlags(t *testing.T) {
	root := &cobra.Command{Use: "pipeleek"}
	root.PersistentFlags().Bool("color", true, "")
	root.PersistentFlags().String("proxy", "https://user:pass@proxy.test", "")

	cmd := &cobra.Command{Use: "scan"}
	cmd.Flags().Bool("artifacts", true, "")
	root.AddCommand(cmd)

	got := scanContextFromCommand(cmd, "https://instance.test", nil)
	if len(got.Options) != 1 || got.Options[0].Name != "--artifacts" {
		t.Fatalf("scan options = %#v, want only the local --artifacts flag", got.Options)
	}
}
