package docs

import (
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"gopkg.in/yaml.v3"

	"github.com/CompassSecurity/pipeleek/pkg/format"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

// GenerateOptions contains options for documentation generation
type GenerateOptions struct {
	RootCmd     *cobra.Command
	Serve       bool
	GithubPages bool
}

func getFileName(cmd *cobra.Command, level int) string {
	switch level {
	case 1:
		if cmd.GroupID != "" {
			return cmd.GroupID + ".md"
		}
		return cmd.Name() + ".md"
	default:
		return cmd.Name() + ".md"
	}
}

func displayName(cmd *cobra.Command, level int) string {
	titleCaser := cases.Title(language.Und, cases.NoLower)
	switch level {
	case 1:
		if cmd.GroupID != "" {
			return titleCaser.String(cmd.GroupID)
		}
		return titleCaser.String(cmd.Name())
	default:
		return titleCaser.String(cmd.Name())
	}
}

func generateDocs(cmd *cobra.Command, dir string, level int, githubPages bool) error {
	var filename string

	if len(cmd.Commands()) > 0 {
		dir = filepath.Join(dir, cmd.Name())
		if err := os.MkdirAll(dir, format.DirUserGroupRead); err != nil {
			return err
		}
		filename = filepath.Join(dir, "index.md")
	} else {
		filename = filepath.Join(dir, getFileName(cmd, level))
	}

	// #nosec G304 - Creating docs markdown file at controlled internal path during docs generation
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	customLinkHandler := func(s string) string {
		if s == "pipeleek.md" {
			return "/"
		}

		s = strings.TrimPrefix(s, "pipeleek_")
		s = strings.TrimSuffix(s, ".md")
		s = strings.ReplaceAll(s, "_", "/")

		// For GitHub Pages, all links need to be prefixed with "pipeleek"
		if githubPages {
			return "/pipeleek/" + s
		}

		return "/" + s
	}

	if err := doc.GenMarkdownCustom(cmd, f, customLinkHandler); err != nil {
		return err
	}

	for _, c := range cmd.Commands() {
		if !c.IsAvailableCommand() || c.IsAdditionalHelpTopicCommand() {
			continue
		}
		if err := generateDocs(c, dir, level+1, githubPages); err != nil {
			return err
		}
	}

	return nil
}

type NavEntry struct {
	Label    string
	FilePath string
	Children []*NavEntry
}

func buildNav(cmd *cobra.Command, level int, parentPath string) *NavEntry {
	entry := &NavEntry{
		Label: displayName(cmd, level),
	}

	if len(cmd.Commands()) > 0 {
		folder := filepath.Join(parentPath, cmd.Name())
		entry.FilePath = filepath.ToSlash(filepath.Join(folder, "index.md"))
		entry.Children = []*NavEntry{}
		for _, c := range cmd.Commands() {
			if !c.IsAvailableCommand() || c.IsAdditionalHelpTopicCommand() {
				continue
			}
			// Skip autocompletion and docs commands from nav menu
			if c.Name() == "completion" || c.Name() == "docs" {
				continue
			}
			entry.Children = append(entry.Children, buildNav(c, level+1, folder))
		}
	} else {
		entry.FilePath = filepath.ToSlash(filepath.Join(parentPath, getFileName(cmd, level)))
	}

	return entry
}

func convertNavToYaml(entries []*NavEntry) []map[string]interface{} {
	yamlList := []map[string]interface{}{}
	for _, e := range entries {
		navPath := e.FilePath
		if len(navPath) >= 9 && navPath[:9] == "pipeleek/" {
			navPath = navPath[9:]
		}
		if len(e.Children) == 0 {
			if filepath.Ext(navPath) == ".md" {
				navPath = navPath[:len(navPath)-3]
			}
			yamlList = append(yamlList, map[string]interface{}{
				e.Label: navPath,
			})
		} else {
			yamlList = append(yamlList, map[string]interface{}{
				e.Label: convertNavToYaml(e.Children),
			})
		}
	}
	return yamlList
}

func writeMkdocsYaml(rootCmd *cobra.Command, outputDir string, githubPages bool) error {
	rootEntry := buildNav(rootCmd, 0, "")
	nav := convertNavToYaml(rootEntry.Children)
	prefix := ""
	if githubPages {
		prefix = "/pipeleek"
	}
	introEntry := map[string]interface{}{
		"Introduction": []map[string]interface{}{
			{"Getting Started": prefix + "/introduction/getting_started/"},
			{"Logging": prefix + "/introduction/logging/"},
			{"Secrets Verification": prefix + "/introduction/secrets_verification/"},
			{"Proxying": prefix + "/introduction/proxying/"},
		},
	}
	guidesEntry := map[string]interface{}{
		"Guides": []map[string]interface{}{
			{"Secret Scanning": prefix + "/guides/scanning/"},
			{"GitLab Pentest": prefix + "/guides/gitlab/"},
			{"Renovate Bot Pentest": prefix + "/guides/renovate/"},
		},
	}
	nav = append([]map[string]interface{}{introEntry, guidesEntry}, nav...)

	assetsDir := filepath.Join(outputDir, "pipeleek", "assets")
	if err := os.MkdirAll(assetsDir, format.DirUserGroupRead); err != nil {
		return err
	}

	assetFiles := []string{"logo.png", "favicon.ico", "social.png", "pipeleek-anim.svg"}
	for _, fname := range assetFiles {
		src := filepath.Join("docs", fname)
		dst := filepath.Join(assetsDir, fname)
		// #nosec G304 - Reading doc assets from controlled internal paths during docs generation
		data, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		// #nosec G306 - Documentation assets should be world-readable
		if err := os.WriteFile(dst, data, format.FilePublicRead); err != nil {
			return err
		}
	}

	mkdocs := map[string]interface{}{
		"site_name":        "Pipeleek",
		"site_description": "Pipeleek scans CI/CD logs and artifacts to detect leaked secrets and pivot from them",
		"site_author":      "FRJ @ Compass Security",
		"site_url":         "https://compasssecurity.github.io/pipeleek/",
		"docs_dir":         "pipeleek",
		"site_dir":         "site",
		"repo_url":         "https://github.com/CompassSecurity/pipeleek",
		"repo_name":        "CompassSecurity/pipeleek",
		"extra_css":        []string{"assets/custom.css"},
		"theme": map[string]interface{}{
			"name":       "material",
			"custom_dir": "pipeleek/overrides",
			"logo":       "assets/logo.png",
			"favicon":    "assets/favicon.ico",
			"palette": []map[string]interface{}{
				{
					"media":   "(prefers-color-scheme: light)",
					"scheme":  "default",
					"primary": "indigo",
					"accent":  "indigo",
					"toggle": map[string]interface{}{
						"icon": "material/brightness-7",
						"name": "Switch to dark mode",
					},
				},
				{
					"media":   "(prefers-color-scheme: dark)",
					"scheme":  "slate",
					"primary": "indigo",
					"accent":  "indigo",
					"toggle": map[string]interface{}{
						"icon": "material/brightness-4",
						"name": "Switch to light mode",
					},
				},
			},
			"features": []string{
				"content.code.copy",
				"content.tabs.link",
				"navigation.tracking",
				"navigation.sections",
				"navigation.expand",
				"navigation.indexes",
				"search.highlight",
				"search.share",
				"search.suggest",
				"toc.follow",
			},
		},
		"extra": map[string]interface{}{
			"social": []map[string]interface{}{
				{
					"icon": "fontawesome/brands/github",
					"link": "https://github.com/CompassSecurity/pipeleek",
					"name": "Pipeleek on GitHub",
				},
			},
			"generator": false,
		},
		"plugins": []map[string]interface{}{
			{"search": map[string]interface{}{
				"separator": "[\\s\\-\\_]",
			}},
			{"minify": map[string]interface{}{
				"minify_html": true,
				"minify_js":   true,
				"minify_css":  true,
			}},
		},
		"markdown_extensions": []interface{}{
			map[string]interface{}{
				"pymdownx.highlight": map[string]interface{}{
					"anchor_linenums":     true,
					"line_spans":          "__span",
					"pygments_lang_class": true,
					"linenums":            true,
				},
			},
			"pymdownx.inlinehilite",
			"pymdownx.snippets",
			"pymdownx.superfences",
			"meta",
			"attr_list",
			"def_list",
			"tables",
			"footnotes",
			"admonition",
			"toc",
			"pymdownx.details",
			"pymdownx.tabbed",
		},
		"nav": nav,
	}

	yamlData, err := yaml.Marshal(mkdocs)
	if err != nil {
		return err
	}

	filename := filepath.Join(outputDir, "mkdocs.yml")
	// #nosec G306 - mkdocs.yml is a public documentation configuration file
	return os.WriteFile(filename, yamlData, format.FilePublicRead)
}

func copySubfolders(srcDir, dstDir string) error {
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			srcPath := filepath.Join(srcDir, entry.Name())
			dstPath := filepath.Join(dstDir, entry.Name())
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
		}
	}
	return nil
}

func copyDir(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, format.DirUserGroupRead); err != nil {
		return err
	}
	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())
		if entry.IsDir() {
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			if err := copyFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	// #nosec G304 - Copying docs files between controlled internal paths during docs generation
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	// #nosec G304 - Creating docs destination file at controlled internal path during docs generation
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()
	_, err = io.Copy(out, in)
	return err
}

func inlineSVGIntoGettingStarted(docsDir string) error {
	// Read the getting_started.md file
	gettingStartedPath := filepath.Join(docsDir, "introduction", "getting_started.md")
	// #nosec G304 - Reading markdown from controlled internal path during docs generation
	mdContent, err := os.ReadFile(gettingStartedPath)
	if err != nil {
		return err
	}

	mdStr := string(mdContent)

	// Find and replace all SVG placeholders
	placeholder := "<!-- INLINE_SVG:pipeleak-anim.svg -->"
	if !strings.Contains(mdStr, placeholder) {
		// No placeholder found, nothing to do
		return nil
	}

	// Read the SVG file from docs source directory (not the copied one)
	svgPath := filepath.Join("docs", "pipeleak-anim.svg")
	// #nosec G304 - Reading SVG from controlled internal path during docs generation
	svgContent, err := os.ReadFile(svgPath)
	if err != nil {
		return err
	}

	// Remove XML declaration from SVG content
	svgStr := string(svgContent)
	svgStr = strings.TrimPrefix(svgStr, `<?xml version="1.0" encoding="utf-8"?>`)
	svgStr = strings.TrimSpace(svgStr)

	// Replace placeholder with inline SVG
	mdStr = strings.Replace(mdStr, placeholder, svgStr, -1)
	// Write the modified content back
	// #nosec G306 - Documentation markdown file should be world-readable
	return os.WriteFile(gettingStartedPath, []byte(mdStr), format.FilePublicRead)
}

// Generate generates the CLI documentation
func Generate(opts GenerateOptions) {
	if _, err := os.Stat("cmd/pipeleek/main.go"); os.IsNotExist(err) {
		log.Fatal().Msg("Run this command from the project root directory.")
	}

	if opts.GithubPages {
		log.Info().Msg("Generating for GitHub Pages")
	}

	outputDir := "./cli-docs"

	if _, err := os.Stat(outputDir); err == nil {
		log.Info().Msg("Output directory exists, deleting...")
		if err := os.RemoveAll(outputDir); err != nil {
			log.Fatal().Err(err).Msg("Failed to delete existing outputDir")
		}
	}

	if err := os.MkdirAll(outputDir, format.DirUserGroupRead); err != nil {
		log.Fatal().Err(err).Msg("Failed to create pipeleek directory")
	}

	if err := copySubfolders("docs", filepath.Join(outputDir, "pipeleek")); err != nil {
		log.Fatal().Err(err).Msg("Failed to copy docs subfolders")
	}

	// Inline SVG into getting_started.md
	if err := inlineSVGIntoGettingStarted(filepath.Join(outputDir, "pipeleek")); err != nil {
		log.Fatal().Err(err).Msg("Failed to inline SVG into getting_started.md")
	}

	opts.RootCmd.DisableAutoGenTag = true
	if err := generateDocs(opts.RootCmd, outputDir, 0, opts.GithubPages); err != nil {
		log.Fatal().Err(err).Msg("Failed to generate CLI docs")
	}

	if err := writeMkdocsYaml(opts.RootCmd, outputDir, opts.GithubPages); err != nil {
		log.Fatal().Err(err).Msg("Failed to write mkdocs.yml")
	}

	log.Info().Str("folder", outputDir).Msg("Markdown successfully generated")

	log.Info().Msg("Running 'mkdocs build' in output folder...")
	cmdRun := exec.Command("mkdocs", "build")
	cmdRun.Dir = outputDir
	cmdRun.Stdout = os.Stdout
	cmdRun.Stderr = os.Stderr
	if err := cmdRun.Run(); err != nil {
		log.Fatal().Err(err).Msg("Failed to run mkdocs build. Is mkdocs installed? pip install mkdocs mkdocs-material mkdocs-minify-plugin")
	}

	if opts.Serve {
		siteDir := filepath.Join(outputDir, "site")
		log.Info().Msgf("Serving docs %s at http://localhost:8000 ... (Ctrl+C to quit)", siteDir)
		http.Handle("/", http.FileServer(http.Dir(siteDir)))

		server := &http.Server{
			Addr:         ":8000",
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 15 * time.Second,
			IdleTimeout:  60 * time.Second,
		}

		if err := server.ListenAndServe(); err != nil {
			log.Fatal().Err(err).Msg("Failed to start HTTP server")
		}
	}
}
