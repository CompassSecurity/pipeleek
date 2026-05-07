package gen_test

import (
	"testing"

	"github.com/CompassSecurity/pipeleek/pkg/config/gen"
	"github.com/spf13/cobra"
)

func TestAllowedConfigPaths_IncludesExpectedPaths(t *testing.T) {
	root := testRootCommandForPaths()
	paths := gen.AllowedConfigPaths(root)

	has := func(target string) bool {
		for _, p := range paths {
			if p == target {
				return true
			}
		}
		return false
	}

	// Only leaf paths (actual settable config values) should be allowed
	expected := []string{"common.threads", "gitlab.gitlab", "gitlab.token", "gitlab.scan.search", "github.scan.org"}
	for _, path := range expected {
		if !has(path) {
			t.Fatalf("expected allowed path %q to exist", path)
		}
	}

	// Intermediate paths should NOT be allowed
	disallowed := []string{"gitlab", "gitlab.scan", "github"}
	for _, path := range disallowed {
		if has(path) {
			t.Fatalf("expected path %q to be disallowed (it's not a leaf)", path)
		}
	}
}

func TestIsAllowedConfigPath(t *testing.T) {
	root := testRootCommandForPaths()
	if !gen.IsAllowedConfigPath(root, "gitlab.scan.search") {
		t.Fatal("expected gitlab.scan.search to be allowed")
	}
	if gen.IsAllowedConfigPath(root, "gitlab.not_real") {
		t.Fatal("expected gitlab.not_real to be disallowed")
	}
}

func TestIsAllowedReadConfigPath(t *testing.T) {
	root := testRootCommandForPaths()

	if !gen.IsAllowedReadConfigPath(root, "gitlab") {
		t.Fatal("expected gitlab section to be readable")
	}
	if !gen.IsAllowedReadConfigPath(root, "gitlab.scan") {
		t.Fatal("expected gitlab.scan section to be readable")
	}
	if !gen.IsAllowedReadConfigPath(root, "gitlab.scan.search") {
		t.Fatal("expected gitlab.scan.search leaf to be readable")
	}
	if gen.IsAllowedReadConfigPath(root, "gitlab.not_real") {
		t.Fatal("expected gitlab.not_real to be disallowed")
	}
}

func testRootCommandForPaths() *cobra.Command {
	root := &cobra.Command{Use: "pipeleek"}

	gl := &cobra.Command{Use: "gl [command]"}
	var gitlabURL string
	var gitlabToken string
	gl.PersistentFlags().StringVarP(&gitlabURL, "gitlab", "g", "https://gitlab.example.com", "GitLab instance URL")
	gl.PersistentFlags().StringVarP(&gitlabToken, "token", "t", "", "GitLab API token")

	scan := &cobra.Command{Use: "scan"}
	var search string
	var threads int
	scan.Flags().StringVarP(&search, "search", "s", "", "Search query")
	scan.Flags().IntVarP(&threads, "threads", "", 4, "Threads")
	gl.AddCommand(scan)

	gh := &cobra.Command{Use: "gh [command]"}
	ghScan := &cobra.Command{Use: "scan"}
	var org string
	ghScan.Flags().StringVarP(&org, "org", "", "", "Organization")
	gh.AddCommand(ghScan)

	root.AddCommand(gl)
	root.AddCommand(gh)
	return root
}
