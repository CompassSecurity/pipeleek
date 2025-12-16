package vuln

import (
	"fmt"
	"strings"

	"code.gitea.io/sdk/gitea"
	"github.com/CompassSecurity/pipeleek/pkg/httpclient"
	"github.com/CompassSecurity/pipeleek/pkg/nist"
	"github.com/rs/zerolog/log"
	"github.com/tidwall/gjson"
)

// RunCheckVulns checks the Gitea instance for vulnerabilities
func RunCheckVulns(giteaUrl, giteaApiToken string) {
	giteaClient, err := gitea.NewClient(giteaUrl, gitea.SetToken(giteaApiToken))
	if err != nil {
		log.Fatal().Err(err).Msg("Failed creating Gitea client")
	}

	version, _, err := giteaClient.ServerVersion()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed determining Gitea version via API")
	}

	// Extract semver from version string (e.g. "1.25.0+dev-623-ga4ccbc9291" -> "1.25.0")
	versionParts := strings.Split(version, "+")
	if len(versionParts) == 0 {
		log.Fatal().Any("versionParts", versionParts).Msg("Failed to determine Gitea version parts")
	}
	extractedVersion := versionParts[0]

	log.Info().Str("version", version).Msg("Gitea")

	log.Debug().Str("version", extractedVersion).Msg("Fetching CVEs for this version")
	httpClient := httpclient.GetPipeleekHTTPClient("", nil, nil)

	cpeName := fmt.Sprintf("cpe:2.3:a:gitea:gitea:%s:*:*:*:*:*:*:*", extractedVersion)

	vulnsJsonStr, err := nist.FetchVulns(httpClient, cpeName)
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
