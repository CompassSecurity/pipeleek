package gen

import (
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

// AllowedConfigPaths returns all allowed config paths derived from currently registered CLI commands.
// It includes both section paths (objects) and leaf paths (flags), e.g.:
//
//	gitlab
//	gitlab.scan
//	gitlab.scan.search
func AllowedConfigPaths(root *cobra.Command) []string {
	tree := &configNode{Children: map[string]*configNode{}, Flags: map[string]flagMeta{}}
	common := map[string]flagMeta{}

	if root != nil {
		buildTreeFromRoot(root, tree, common)
	}

	allowed := map[string]struct{}{}

	if len(common) > 0 {
		allowed["common"] = struct{}{}
		for key := range common {
			allowed["common."+key] = struct{}{}
		}
	}

	for platform, node := range tree.Children {
		collectNodePaths(node, platform, allowed)
	}

	paths := make([]string, 0, len(allowed))
	for p := range allowed {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths
}

// IsAllowedConfigPath returns true when the given dotted key path is part of the generated config schema.
func IsAllowedConfigPath(root *cobra.Command, path string) bool {
	normalized := normalizePath(path)
	if normalized == "" {
		return false
	}
	for _, p := range AllowedConfigPaths(root) {
		if p == normalized {
			return true
		}
	}
	return false
}

func collectNodePaths(node *configNode, prefix string, allowed map[string]struct{}) {
	if node == nil {
		return
	}

	// Only add this node's prefix if it's an empty leaf (no children, no flags).
	// Don't add command nodes that have flags - the individual flag paths should be allowed, not the command path itself.
	hasFlags := len(node.Flags) > 0
	hasChildren := len(node.Children) > 0
	isEmpty := !hasFlags && !hasChildren

	if prefix != "" && isEmpty {
		allowed[prefix] = struct{}{}
	}

	// Add all flag paths (these are always allowed as individual config keys)
	for flag := range node.Flags {
		if prefix == "" {
			allowed[flag] = struct{}{}
			continue
		}
		allowed[prefix+"."+flag] = struct{}{}
	}

	// Recurse into children
	for childName, childNode := range node.Children {
		childPrefix := childName
		if prefix != "" {
			childPrefix = prefix + "." + childName
		}
		collectNodePaths(childNode, childPrefix, allowed)
	}
}

func normalizePath(path string) string {
	segments := strings.Split(path, ".")
	norm := make([]string, 0, len(segments))
	for _, segment := range segments {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}
		norm = append(norm, normalizeSegment(segment))
	}
	return strings.Join(norm, ".")
}
