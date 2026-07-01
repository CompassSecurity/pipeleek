package docs

import (
	pkgdocs "github.com/CompassSecurity/pipeleek/pkg/docs"
	"github.com/spf13/cobra"
)

// docsRoot holds the root command reference needed by the docs generator.
// It is set once by NewDocsCmd and never mutated afterwards.
var docsRoot *cobra.Command

// RunDocs is the named handler for the docs command.
func RunDocs(cmd *cobra.Command, args []string) {
	serve, _ := cmd.Flags().GetBool("serve")
	githubPages, _ := cmd.Flags().GetBool("github-pages")
	pkgdocs.Generate(pkgdocs.GenerateOptions{
		RootCmd:     docsRoot,
		Serve:       serve,
		GithubPages: githubPages,
	})
}

func NewDocsCmd(root *cobra.Command) *cobra.Command {
	docsRoot = root

	cmd := &cobra.Command{
		Use:   "docs",
		Short: "Generate CLI documentation",
		Long:  "Generates documentation for all commands. Must be run in an environment where 'mkdocs' is installed.",
		Example: `
# Generate docs and serve them at http://localhost:8000
pipeleek docs --serve
		`,
		Run: RunDocs,
	}

	cmd.Flags().BoolVarP(new(bool), "serve", "s", false, "Serve documentation after building")
	cmd.Flags().BoolVarP(new(bool), "github-pages", "g", false, "Build for GitHub Pages")

	return cmd
}
