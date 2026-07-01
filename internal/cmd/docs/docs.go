package docs

import (
	pkgdocs "github.com/CompassSecurity/pipeleek/pkg/docs"
	"github.com/spf13/cobra"
)

type docsCommand struct {
	root        *cobra.Command
	serve       *bool
	githubPages *bool
}

func (d docsCommand) Run(_ *cobra.Command, _ []string) {
	runDocs(d.root, *d.serve, *d.githubPages)
}

func runDocs(root *cobra.Command, serve bool, githubPages bool) {
	pkgdocs.Generate(pkgdocs.GenerateOptions{
		RootCmd:     root,
		Serve:       serve,
		GithubPages: githubPages,
	})
}

func NewDocsCmd(root *cobra.Command) *cobra.Command {
	var serve bool
	var githubPages bool
	runner := docsCommand{root: root, serve: &serve, githubPages: &githubPages}

	cmd := &cobra.Command{
		Use:   "docs",
		Short: "Generate CLI documentation",
		Long:  "Generates documentation for all commands. Must be run in an environment where 'mkdocs' is installed.",
		Example: `
# Generate docs and serve them at http://localhost:8000
pipeleek docs --serve
		`,
		Run: runner.Run,
	}

	cmd.Flags().BoolVarP(&serve, "serve", "s", false, "Serve documentation after building")
	cmd.Flags().BoolVarP(&githubPages, "github-pages", "g", false, "Build for GitHub Pages")

	return cmd
}
