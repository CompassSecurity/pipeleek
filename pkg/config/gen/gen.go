package gen

import (
	"bytes"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"gopkg.in/yaml.v3"
)

type configNode struct {
	Children map[string]*configNode
	Flags    map[string]flagMeta
}

type flagMeta struct {
	Value  *yaml.Node
	EnvVar string
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
	tree := &configNode{Children: map[string]*configNode{}, Flags: map[string]flagMeta{}}
	common := map[string]flagMeta{}

	if root != nil {
		buildTreeFromRoot(root, tree, common)
	}

	rootMap := newMappingNode()
	rootMap.HeadComment = strings.Join([]string{
		"Pipeleek Configuration File (YAML)",
		"Generated dynamically from currently registered CLI commands and flags.",
	}, "\n")

	if len(common) > 0 {
		appendMappingPair(rootMap, "common", flagsToMappingNode(common))
	}

	platformNames := make([]string, 0, len(tree.Children))
	for name := range tree.Children {
		platformNames = append(platformNames, name)
	}
	sort.Strings(platformNames)

	for _, platform := range platformNames {
		appendMappingPair(rootMap, platform, configNodeToYAMLNode(tree.Children[platform]))
	}

	var out bytes.Buffer
	encoder := yaml.NewEncoder(&out)
	encoder.SetIndent(2)
	if err := encoder.Encode(rootMap); err != nil {
		_ = encoder.Close()
		return ""
	}
	if err := encoder.Close(); err != nil {
		return ""
	}

	return out.String()
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
		value := yamlNodeFromFlag(flag)

		if _, isCommon := commonFlagNames[flag.Name]; isCommon {
			common[flagName] = flagMeta{
				Value:  value,
				EnvVar: envVarForPath([]string{"common", flagName}),
			}
			return
		}

		if node.Flags == nil {
			node.Flags = map[string]flagMeta{}
		}
		node.Flags[flagName] = flagMeta{
			Value:  value,
			EnvVar: envVarForPath(append(keyPrefix, flagName)),
		}
	})
}

func configNodeToYAMLNode(node *configNode) *yaml.Node {
	mapping := newMappingNode()
	if node == nil {
		return mapping
	}

	if len(node.Flags) > 0 {
		flagNames := make([]string, 0, len(node.Flags))
		for name := range node.Flags {
			flagNames = append(flagNames, name)
		}
		sort.Strings(flagNames)

		for _, name := range flagNames {
			meta := node.Flags[name]
			value := cloneYAMLNode(meta.Value)
			if value == nil {
				value = quotedStringNode("")
			}
			if meta.EnvVar != "" {
				value.LineComment = meta.EnvVar
			}
			appendMappingPair(mapping, name, value)
		}
	}

	if len(node.Children) > 0 {
		childNames := make([]string, 0, len(node.Children))
		for name := range node.Children {
			childNames = append(childNames, name)
		}
		sort.Strings(childNames)

		for _, name := range childNames {
			appendMappingPair(mapping, name, configNodeToYAMLNode(node.Children[name]))
		}
	}

	return mapping
}

func flagsToMappingNode(flags map[string]flagMeta) *yaml.Node {
	mapping := newMappingNode()
	flagNames := make([]string, 0, len(flags))
	for name := range flags {
		flagNames = append(flagNames, name)
	}
	sort.Strings(flagNames)

	for _, name := range flagNames {
		meta := flags[name]
		value := cloneYAMLNode(meta.Value)
		if value == nil {
			value = quotedStringNode("")
		}
		if meta.EnvVar != "" {
			value.LineComment = meta.EnvVar
		}
		appendMappingPair(mapping, name, value)
	}

	return mapping
}

func newMappingNode() *yaml.Node {
	return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
}

func appendMappingPair(mapping *yaml.Node, key string, value *yaml.Node) {
	if mapping == nil {
		return
	}
	if value == nil {
		value = quotedStringNode("")
	}
	mapping.Content = append(mapping.Content, plainStringNode(key), value)
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
	normalized := replacer.Replace(strings.TrimSpace(value))
	if normalized == "truffle_hog_verification" {
		return "trufflehog_verification"
	}
	return normalized
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

func yamlNodeFromFlag(flag *pflag.Flag) *yaml.Node {
	switch flag.Value.Type() {
	case "bool":
		return boolNode(flag.DefValue == "true")
	case "int", "int32", "int64", "uint", "uint32", "uint64":
		return plainScalarNode(flag.DefValue, "!!int")
	case "float32", "float64":
		return plainScalarNode(flag.DefValue, "!!float")
	case "stringSlice", "intSlice", "durationSlice":
		return flowSequenceNode(parseSliceDefault(flag.DefValue))
	case "duration", "string":
		return quotedStringNode(flag.DefValue)
	default:
		trimmed := strings.TrimSpace(flag.DefValue)
		if trimmed == "" {
			return quotedStringNode("")
		}
		return quotedStringNode(flag.DefValue)
	}
}

func parseSliceDefault(def string) []string {
	trimmed := strings.TrimSpace(def)
	if trimmed == "" || trimmed == "[]" {
		return []string{}
	}
	if !strings.HasPrefix(trimmed, "[") || !strings.HasSuffix(trimmed, "]") {
		return []string{}
	}

	inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(trimmed, "["), "]"))
	if inner == "" {
		return []string{}
	}

	parts := strings.Split(inner, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		values = append(values, strings.TrimSpace(part))
	}
	return values
}

func plainStringNode(value string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
}

func quotedStringNode(value string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value, Style: yaml.DoubleQuotedStyle}
}

func plainScalarNode(value string, tag string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: value}
}

func boolNode(value bool) *yaml.Node {
	if value {
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true"}
	}
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "false"}
}

func flowSequenceNode(values []string) *yaml.Node {
	sequence := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle}
	for _, value := range values {
		sequence.Content = append(sequence.Content, quotedStringNode(value))
	}
	return sequence
}

func cloneYAMLNode(node *yaml.Node) *yaml.Node {
	if node == nil {
		return nil
	}
	clone := *node
	if len(node.Content) > 0 {
		clone.Content = make([]*yaml.Node, 0, len(node.Content))
		for _, child := range node.Content {
			clone.Content = append(clone.Content, cloneYAMLNode(child))
		}
	}
	return &clone
}
