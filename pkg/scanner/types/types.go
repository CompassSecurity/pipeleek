package types

type SecretsPatterns struct {
	Patterns []PatternElement `json:"patterns"`
}

type PatternElement struct {
	Pattern PatternPattern `json:"pattern"`
}

type PatternPattern struct {
	Name       string `json:"name"`
	Regex      string `json:"regex"`
	Confidence string `json:"confidence"`
}

type Finding struct {
	Pattern PatternElement
	Text    string
	Engine  string
}

type DetectionResult struct {
	Findings []Finding
	Error    error
}
