package result

import (
	"github.com/CompassSecurity/pipeleek/pkg/logging"
	"github.com/CompassSecurity/pipeleek/pkg/scanner"
)

type ReportOptions struct {
	LocationURL string
	JobName     string
	BuildName   string
	Type        logging.SecretType
}

func ReportFindings(findings []scanner.Finding, opts ReportOptions) {
	for _, finding := range findings {
		ReportFinding(finding, opts)
	}
}

func ReportFinding(finding scanner.Finding, opts ReportOptions) {
	secretType := opts.Type
	if secretType == "" {
		secretType = logging.SecretTypeLog
	}

	event := logging.Hit().
		Str("type", string(secretType)).
		Str("confidence", finding.Pattern.Pattern.Confidence).
		Str("ruleName", finding.Pattern.Pattern.Name).
		Str("value", finding.Text).
		Engine(finding.Engine)

	// Add location information if provided
	if opts.LocationURL != "" {
		event = event.Str("url", opts.LocationURL)
	}
	if opts.JobName != "" {
		event = event.Str("job", opts.JobName)
	}
	if opts.BuildName != "" {
		event = event.Str("build", opts.BuildName)
	}

	event.Msg("SECRET")
}

func ReportFindingWithCustomFields(finding scanner.Finding, customFields map[string]string) {
	// Extract type from custom fields if present, default to LOG
	secretType := logging.SecretTypeLog
	if t, ok := customFields["type"]; ok {
		secretType = logging.SecretType(t)
		delete(customFields, "type")
	}

	event := logging.Hit().
		Str("type", string(secretType)).
		Str("confidence", finding.Pattern.Pattern.Confidence).
		Str("ruleName", finding.Pattern.Pattern.Name).
		Str("value", finding.Text).
		Engine(finding.Engine)

	for key, value := range customFields {
		event = event.Str(key, value)
	}

	event.Msg("SECRET")
}
