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
		"--cookie",
		"--local-filter",
		"--repository",
		"--secrets-verification",
		"--threads",
		"--token",
	}
	if !reflect.DeepEqual(names, wantNames) {
		t.Fatalf("option names = %v, want %v", names, wantNames)
	}
	wantValues := map[string]string{
		"--cookie":               "config-cookie",
		"--local-filter":         "selected",
		"--repository":           "owner/project",
		"--secrets-verification": "true",
		"--threads":              "8",
		"--token":                "config-token",
	}
	if !reflect.DeepEqual(values, wantValues) {
		t.Fatalf("option values = %v, want %v", values, wantValues)
	}
}

func TestIsEnabledScanFlag(t *testing.T) {
	tests := []struct {
		name  string
		value interface{}
		want  bool
	}{
		{name: "true boolean", value: true, want: true},
		{name: "false boolean", value: false},
		{name: "non-empty string", value: "selected", want: true},
		{name: "empty string", value: ""},
		{name: "false string", value: "false"},
		{name: "zero integer", value: 0},
		{name: "positive integer", value: 4, want: true},
		{name: "zero duration", value: time.Duration(0)},
		{name: "positive duration", value: time.Minute, want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isEnabledScanFlag(test.value); got != test.want {
				t.Fatalf("isEnabledScanFlag(%#v) = %t, want %t", test.value, got, test.want)
			}
		})
	}
}
