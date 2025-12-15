package vuln

import (
	"os"

	"github.com/CompassSecurity/pipeleek/pkg/gitea/nist"
	"github.com/CompassSecurity/pipeleek/pkg/gitea/util"
	"github.com/CompassSecurity/pipeleek/pkg/httpclient"
	"github.com/rs/zerolog/log"
	"github.com/tidwall/gjson"
)

// RunCheckVulns checks the Gitea instance for vulnerabilities
func RunCheckVulns(giteaUrl, giteaApiToken string) {
	installedVersion := util.DetermineVersion(giteaUrl, giteaApiToken)
	log.Info().Str("version", installedVersion.Version).Msg("Gitea")

	log.Info().Str("version", installedVersion.Version).Msg("Fetching CVEs for this version")
	client := httpclient.GetPipeleekHTTPClient("", nil, nil)
	baseURL := "https://services.nvd.nist.gov/rest/json/cves/2.0"

	// Allow overriding NIST base URL via environment variable (primarily for testing)
	if envURL := os.Getenv("PIPELEEK_NIST_BASE_URL"); envURL != "" {
		baseURL = envURL
	}

	vulnsJsonStr, err := nist.FetchVulns(client, baseURL, installedVersion.Version)
	if err != nil {
		log.Fatal().Msg("Unable fetch vulnerabilities from NIST")
	}

	result := gjson.Get(vulnsJsonStr, "vulnerabilities")
	result.ForEach(func(key, value gjson.Result) bool {
		cve := value.Get("cve.id").String()
		description := value.Get("cve.descriptions.0.value").String()
		log.Info().Str("cve", cve).Str("description", description).Msg("Vulnerable")
		return true
	})

	log.Info().Msg("Finished vuln scan")
}
