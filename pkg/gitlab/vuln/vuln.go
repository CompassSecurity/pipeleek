package vuln

import (
	"fmt"

	"github.com/CompassSecurity/pipeleek/pkg/gitlab/util"
	"github.com/CompassSecurity/pipeleek/pkg/httpclient"
	"github.com/CompassSecurity/pipeleek/pkg/nist"
	"github.com/rs/zerolog/log"
	"github.com/tidwall/gjson"
)

// RunCheckVulns checks the GitLab instance for vulnerabilities
func RunCheckVulns(gitlabUrl, gitlabApiToken string) {
	installedVersion := util.DetermineVersion(gitlabUrl, gitlabApiToken)
	log.Info().Str("version", installedVersion.Version).Msg("GitLab")

	log.Debug().Str("version", installedVersion.Version).Msg("Fetching CVEs for this version")
	client := httpclient.GetPipeleekHTTPClient("", nil, nil)

	edition := "community"
	if installedVersion.Enterprise {
		edition = "enterprise"
	}
	cpeName := fmt.Sprintf("cpe:2.3:a:gitlab:gitlab:%s:*:*:*:%s:*:*:*", installedVersion.Version, edition)

	vulnsJsonStr, err := nist.FetchVulns(client, cpeName)
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
