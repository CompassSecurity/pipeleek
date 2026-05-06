package gen

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type configNode struct {
	Children map[string]*configNode
	Flags    map[string]flagMeta
}

type flagMeta struct {
	DefaultValue string
	EnvVar       string
}

var commonFlagNames = map[string]struct{}{
	"threads":                  {},
	"truffle-hog-verification": {},
	"max-artifact-size":        {},
	"confidence":               {},
	"hit-timeout":              {},
}

var rootFlagsToSkip = map[string]struct{}{
	"config":       {},
	"json":         {},
	"logfile":      {},
	"verbose":      {},
	"log-level":    {},
	"color":        {},
	"ignore-proxy": {},
	"help":         {},
	"version":      {},
	"output":       {},
}

var platformNameByCommand = map[string]string{
	"gl":      "gitlab",
	"gluna":   "gitlab",
	"gh":      "github",
	"bb":      "bitbucket",
	"ad":      "azure_devops",
	"gitea":   "gitea",
	"jenkins": "jenkins",
	"circle":  "circle",
}

// GenerateExampleConfig builds a YAML template from the currently registered CLI commands and flags.
func GenerateExampleConfig(root *cobra.Command) string {
	node := &configNode{Children: map[string]*configNode{}, Flags: map[string]flagMeta{}}
	common := map[string]flagMeta{}

	if root != nil {
		buildTreeFromRoot(root, node, common)
	}

	var b strings.Builder
	b.WriteString("# Pipeleek Configuration File (YAML)\n")
	b.WriteString("# Generated dynamically from currently registered CLI commands and flags.\n\n")

	if len(common) > 0 {
		b.WriteString("common:\n")
		writeFlags(&b, common, 1)
		b.WriteString("\n")
	}

	platformNames := make([]string, 0, len(node.Children))
	for name := range node.Children {
		platformNames = append(platformNames, name)
	}
	sort.Strings(platformNames)

	for i, platform := range platformNames {
		b.WriteString(platform)
		b.WriteString(":\n")
		writeNode(&b, node.Children[platform], 1)
		if i < len(platformNames)-1 {
			b.WriteString("\n")
		}
	}

	return b.String()
}

func buildTreeFromRoot(root *cobra.Command, rootNode *configNode, common map[string]flagMeta) {
	for _, sub := range root.Commands() {
		cmdName := commandName(sub)
		platformName, ok := platformNameByCommand[cmdName]
		if !ok {
			continue
		}

		platformNode := ensureChild(rootNode, platformName)

		if cmdName == "gluna" {
			visitCommand(sub, platformName, platformNode, []string{}, common, true)
			continue
		}

		captureFlags(sub.PersistentFlags(), []string{platformName}, platformNode, common)
		visitCommand(sub, platformName, platformNode, []string{}, common, false)
	}
}

func visitCommand(cmd *cobra.Command, platformName string, platformNode *configNode, path []string, common map[string]flagMeta, includeLocal bool) {
	currentPath := append([]string{}, path...)
	if includeLocal {
		name := normalizeSegment(commandName(cmd))

		if commandName(cmd) == "scan" && len(path) == 0 && cmd.Parent() != nil && commandName(cmd.Parent()) == "gluna" {
			currentPath = append(path, "scan_public")
		} else {
			currentPath = append(currentPath, name)
		}

		captureFlags(cmd.Flags(), append([]string{platformName}, currentPath...), platformNodeForPath(platformNode, currentPath), common)
	}

	for _, sub := range cmd.Commands() {
		if sub.Hidden {
			continue
		}
		visitCommand(sub, platformName, platformNode, currentPath, common, true)
	}
}

func platformNodeForPath(platformNode *configNode, path []string) *configNode {
	n := platformNode
	for _, segment := range path {
		n = ensureChild(n, segment)
	}
	return n
}

func captureFlags(flagSet *pflag.FlagSet, keyPrefix []string, node *configNode, common map[string]flagMeta) {
	if flagSet == nil {
		return
	}

	flagSet.VisitAll(func(flag *pflag.Flag) {
		if _, skip := rootFlagsToSkip[flag.Name]; skip {
			return
		}

		flagName := normalizeSegment(flag.Name)
		defaultValue := yamlValueFromFlag(flag)

		if _, isCommon := commonFlagNames[flag.Name]; isCommon {
			common[flagName] = flagMeta{
				DefaultValue: defaultValue,
				EnvVar:       envVarForPath([]string{"common", flagName}),
			}
			return
		}

		if node.Flags == nil {
			node.Flags = map[string]flagMeta{}
		}
		node.Flags[flagName] = flagMeta{
			DefaultValue: defaultValue,
			EnvVar:       envVarForPath(append(keyPrefix, flagName)),
		}
	})
}

func writeNode(b *strings.Builder, node *configNode, indent int) {
	if node == nil {
		return
	}

	if len(node.Flags) > 0 {
		writeFlags(b, node.Flags, indent)
	}

	childNames := make([]string, 0, len(node.Children))
	for name := range node.Children {
		childNames = append(childNames, name)
	}
	sort.Strings(childNames)

	for _, child := range childNames {
		writeIndent(b, indent)
		b.WriteString(child)
		b.WriteString(":\n")
		writeNode(b, node.Children[child], indent+1)
	}
}

func writeFlags(b *strings.Builder, flags map[string]flagMeta, indent int) {
	flagNames := make([]string, 0, len(flags))
	for name := range flags {
		flagNames = append(flagNames, name)
	}
	sort.Strings(flagNames)

	for _, name := range flagNames {
		meta := flags[name]
		writeIndent(b, indent)
		b.WriteString(name)
		b.WriteString(": ")
		b.WriteString(meta.DefaultValue)
		if meta.EnvVar != "" {
			b.WriteString(" # ")
			b.WriteString(meta.EnvVar)
		}
		b.WriteString("\n")
	}
}

func ensureChild(node *configNode, name string) *configNode {
	if node.Children == nil {
		node.Children = map[string]*configNode{}
	}
	child, ok := node.Children[name]
	if !ok {
		child = &configNode{Children: map[string]*configNode{}, Flags: map[string]flagMeta{}}
		node.Children[name] = child
	}
	return child
}

func commandName(cmd *cobra.Command) string {
	if cmd == nil {
		return ""
	}
	parts := strings.Fields(cmd.Use)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

func normalizeSegment(value string) string {
	replacer := strings.NewReplacer("-", "_", " ", "_")
	return replacer.Replace(strings.TrimSpace(value))
}

func envVarForPath(path []string) string {
	filtered := make([]string, 0, len(path))
	for _, segment := range path {
		if segment == "" {
			continue
		}
		filtered = append(filtered, strings.ToUpper(normalizeSegment(segment)))
	}
	return "PIPELEEK_" + strings.Join(filtered, "_")
}

func yamlValueFromFlag(flag *pflag.Flag) string {
	switch flag.Value.Type() {
	case "bool":
		if flag.DefValue == "true" {
			return "true"
		}
		return "false"
	case "int", "int32", "int64", "uint", "uint32", "uint64", "float32", "float64":
		return flag.DefValue
	case "stringSlice", "intSlice", "durationSlice":
		trimmed := strings.TrimSpace(flag.DefValue)
		if trimmed == "" || trimmed == "[]" {
			return "[]"
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(trimmed, "["), "]"))
			if inner == "" {
				return "[]"
			}
			parts := strings.Split(inner, ",")
			vals := make([]string, 0, len(parts))
			for _, part := range parts {
				vals = append(vals, quoteYAMLString(strings.TrimSpace(part)))
			}
			return "[" + strings.Join(vals, ", ") + "]"
		}
		return "[]"
	case "duration":
		return quoteYAMLString(flag.DefValue)
	case "string":
		return quoteYAMLString(flag.DefValue)
	default:
		if strings.TrimSpace(flag.DefValue) == "" {
			return `""`
		}
		if isLikelyPlainScalar(flag.DefValue) {
			return flag.DefValue
		}
		return quoteYAMLString(flag.DefValue)
	}
}

func isLikelyPlainScalar(value string) bool {
	if value == "" {
		return false
	}
	if _, err := strconv.Atoi(value); err == nil {
		return true
	}
	if value == "true" || value == "false" {
		return true
	}
	if strings.ContainsAny(value, "#:[]{}\",'\n\t") {
		return false
	}
	return true
}

func quoteYAMLString(value string) string {
	return fmt.Sprintf("%q", value)
}

func writeIndent(b *strings.Builder, indent int) {
	for i := 0; i < indent; i++ {
		b.WriteString("  ")
	}
}
