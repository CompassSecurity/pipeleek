package vuln

import (
	"fmt"
	"os"
	"strings"

	"github.com/CompassSecurity/pipeleek/pkg/gitea/util"
	"github.com/CompassSecurity/pipeleek/pkg/httpclient"
	"github.com/CompassSecurity/pipeleek/pkg/nist"
	"github.com/rs/zerolog/log"
	"github.com/tidwall/gjson"
)

// RunCheckVulns checks the Gitea instance for vulnerabilities
func RunCheckVulns(giteaUrl, giteaApiToken string) {
	installedVersion := util.DetermineVersion(giteaUrl, giteaApiToken)

	// Extract semver from version string (e.g. "1.25.0+dev-623-ga4ccbc9291" -> "1.25.0")
	versionParts := strings.Split(installedVersion.Version, "+")
	extractedVersion := versionParts[0]

	log.Info().Str("version", installedVersion.Version).Msg("Gitea")

	log.Debug().Str("version", extractedVersion).Msg("Fetching CVEs for this version")
	client := httpclient.GetPipeleekHTTPClient("", nil, nil)
	baseURL := "https://services.nvd.nist.gov/rest/json/cves/2.0"

	// Allow overriding NIST base URL via environment variable (primarily for testing)
	if envURL := os.Getenv("PIPELEEK_NIST_BASE_URL"); envURL != "" {
		baseURL = envURL
	}

	cpeName := fmt.Sprintf("cpe:2.3:a:gitea:gitea:%s:*:*:*:*:*:*:*", extractedVersion)

	vulnsJsonStr, err := nist.FetchVulns(client, baseURL, cpeName)
	if err != nil {
		log.Fatal().Msg("Unable to fetch vulnerabilities from NIST")
	}

	result := gjson.Get(vulnsJsonStr, "vulnerabilities")
	result.ForEach(func(key, value gjson.Result) bool {
		cve := value.Get("cve.id").String()
		description := value.Get("cve.descriptions.0.value").String()
		log.Warn().Str("cve", cve).Str("description", description).Msg("Vulnerable")
		return true
	})

	log.Info().Msg("Finished vuln scan")
}
