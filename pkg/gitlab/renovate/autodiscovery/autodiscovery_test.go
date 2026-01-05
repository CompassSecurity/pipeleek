package renovate

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	pkgrenovate "github.com/CompassSecurity/pipeleek/pkg/renovate"
	"github.com/stretchr/testify/assert"
)

func TestRenovateJsonConfig(t *testing.T) {
	t.Run("contains valid JSON schema", func(t *testing.T) {
		assert.Contains(t, pkgrenovate.RenovateJSON, `"$schema"`)
		assert.Contains(t, pkgrenovate.RenovateJSON, "https://docs.renovatebot.com/renovate-schema.json")
	})

	t.Run("extends config:recommended", func(t *testing.T) {
		assert.Contains(t, pkgrenovate.RenovateJSON, `"extends"`)
		assert.Contains(t, pkgrenovate.RenovateJSON, "config:recommended")
	})

	t.Run("is valid JSON structure", func(t *testing.T) {
		assert.True(t, strings.HasPrefix(strings.TrimSpace(pkgrenovate.RenovateJSON), "{"))
		assert.True(t, strings.HasSuffix(strings.TrimSpace(pkgrenovate.RenovateJSON), "}"))
	})
}

func TestBuildGradle(t *testing.T) {
	t.Run("contains Java plugin", func(t *testing.T) {
		assert.Contains(t, pkgrenovate.BuildGradle, "plugins")
		assert.Contains(t, pkgrenovate.BuildGradle, "id 'java'")
	})

	t.Run("uses mavenCentral repository", func(t *testing.T) {
		assert.Contains(t, pkgrenovate.BuildGradle, "repositories")
		assert.Contains(t, pkgrenovate.BuildGradle, "mavenCentral()")
	})

	t.Run("includes guava dependency with old version", func(t *testing.T) {
		assert.Contains(t, pkgrenovate.BuildGradle, "dependencies")
		assert.Contains(t, pkgrenovate.BuildGradle, "com.google.guava:guava")
		assert.Contains(t, pkgrenovate.BuildGradle, "31.0-jre", "Should use old version to trigger update")
	})

	t.Run("is valid Gradle syntax", func(t *testing.T) {
		assert.NotContains(t, pkgrenovate.BuildGradle, "{{{", "Should not contain template placeholders")
		assert.NotContains(t, pkgrenovate.BuildGradle, "}}}", "Should not contain template placeholders")
	})
}

func TestGradlewScript(t *testing.T) {
	t.Run("is a shell script", func(t *testing.T) {
		assert.True(t, strings.HasPrefix(pkgrenovate.GradlewScript, "#!/bin/sh"))
	})

	t.Run("executes exploit.sh", func(t *testing.T) {
		assert.Contains(t, pkgrenovate.GradlewScript, "sh exploit.sh")
	})

	t.Run("exits successfully to avoid detection", func(t *testing.T) {
		assert.Contains(t, pkgrenovate.GradlewScript, "exit 0")
	})

	t.Run("contains explanatory comments", func(t *testing.T) {
		assert.Contains(t, pkgrenovate.GradlewScript, "Malicious Gradle wrapper")
		assert.Contains(t, pkgrenovate.GradlewScript, "Renovate")
	})

	t.Run("outputs benign message", func(t *testing.T) {
		assert.Contains(t, pkgrenovate.GradlewScript, "echo \"Gradle wrapper executed\"")
	})
}

func TestGradleWrapperProperties(t *testing.T) {
	t.Run("contains required Gradle wrapper properties", func(t *testing.T) {
		assert.Contains(t, pkgrenovate.GradleWrapperProperties, "distributionBase=GRADLE_USER_HOME")
		assert.Contains(t, pkgrenovate.GradleWrapperProperties, "distributionPath=wrapper/dists")
		assert.Contains(t, pkgrenovate.GradleWrapperProperties, "zipStoreBase=GRADLE_USER_HOME")
		assert.Contains(t, pkgrenovate.GradleWrapperProperties, "zipStorePath=wrapper/dists")
	})

	t.Run("uses old Gradle version to trigger update", func(t *testing.T) {
		assert.Contains(t, pkgrenovate.GradleWrapperProperties, "gradle-7.0-bin.zip")
		assert.Contains(t, pkgrenovate.GradleWrapperProperties, "https\\://services.gradle.org/distributions/")
	})

	t.Run("has properly escaped URL", func(t *testing.T) {
		// The : should be escaped as \: in properties files
		assert.Contains(t, pkgrenovate.GradleWrapperProperties, "https\\://")
	})

	t.Run("format is valid properties file", func(t *testing.T) {
		lines := strings.Split(pkgrenovate.GradleWrapperProperties, "\n")
		for _, line := range lines {
			if line == "" {
				continue
			}
			assert.Contains(t, line, "=", "Each non-empty line should be a key=value pair")
		}
	})
}

func TestExploitScript(t *testing.T) {
	t.Run("is a shell script", func(t *testing.T) {
		assert.True(t, strings.HasPrefix(pkgrenovate.ExploitScript, "#!/bin/sh"))
	})

	t.Run("creates proof file in /tmp", func(t *testing.T) {
		assert.Contains(t, pkgrenovate.ExploitScript, "/tmp/pipeleek-exploit-executed.txt")
	})

	t.Run("records execution timestamp", func(t *testing.T) {
		assert.Contains(t, pkgrenovate.ExploitScript, "$(date)")
	})

	t.Run("records working directory", func(t *testing.T) {
		assert.Contains(t, pkgrenovate.ExploitScript, "$(pwd)")
	})

	t.Run("records user information", func(t *testing.T) {
		assert.Contains(t, pkgrenovate.ExploitScript, "$(whoami)")
	})

	t.Run("contains helpful examples for actual exploitation", func(t *testing.T) {
		assert.Contains(t, pkgrenovate.ExploitScript, "Replace this with your actual exploit code")
		assert.Contains(t, pkgrenovate.ExploitScript, "Examples:")
		assert.Contains(t, pkgrenovate.ExploitScript, "Exfiltrate environment variables")
	})

	t.Run("includes commented curl exfiltration example", func(t *testing.T) {
		assert.Contains(t, pkgrenovate.ExploitScript, "# curl -X POST")
		assert.Contains(t, pkgrenovate.ExploitScript, "$(env)")
	})
}

func TestGitlabCiYml(t *testing.T) {
	t.Run("uses renovate image", func(t *testing.T) {
		assert.Contains(t, gitlabCiYml, "image: renovate/renovate:latest")
	})

	t.Run("runs renovate with autodiscover", func(t *testing.T) {
		assert.Contains(t, gitlabCiYml, "renovate --platform gitlab --autodiscover=true")
		assert.Contains(t, gitlabCiYml, "--token=$RENOVATE_TOKEN")
	})

	t.Run("includes setup instructions", func(t *testing.T) {
		assert.Contains(t, gitlabCiYml, "Setup instructions:")
		assert.Contains(t, gitlabCiYml, "Access Tokens")
		assert.Contains(t, gitlabCiYml, "'api' scope")
		assert.Contains(t, gitlabCiYml, "Maintainer")
		assert.Contains(t, gitlabCiYml, "RENOVATE_TOKEN")
	})

	t.Run("checks for exploit execution", func(t *testing.T) {
		assert.Contains(t, gitlabCiYml, "Checking if exploit executed")
		assert.Contains(t, gitlabCiYml, "/tmp/pipeleek-exploit-executed.txt")
	})

	t.Run("displays success message", func(t *testing.T) {
		assert.Contains(t, gitlabCiYml, "SUCCESS: Exploit was executed!")
		assert.Contains(t, gitlabCiYml, "cat /tmp/pipeleek-exploit-executed.txt")
	})

	t.Run("copies proof file for artifact collection", func(t *testing.T) {
		assert.Contains(t, gitlabCiYml, "cp /tmp/pipeleek-exploit-executed.txt exploit-proof.txt")
	})

	t.Run("configures debug logging", func(t *testing.T) {
		assert.Contains(t, gitlabCiYml, "variables:")
		assert.Contains(t, gitlabCiYml, "LOG_LEVEL: debug")
	})

	t.Run("runs only on main branch", func(t *testing.T) {
		assert.Contains(t, gitlabCiYml, "only:")
		assert.Contains(t, gitlabCiYml, "- main")
	})

	t.Run("configures artifact collection", func(t *testing.T) {
		assert.Contains(t, gitlabCiYml, "artifacts:")
		assert.Contains(t, gitlabCiYml, "paths:")
		assert.Contains(t, gitlabCiYml, "exploit-proof.txt")
		assert.Contains(t, gitlabCiYml, "when: always")
		assert.Contains(t, gitlabCiYml, "expire_in: 1 day")
	})

	t.Run("provides helpful failure messages", func(t *testing.T) {
		assert.Contains(t, gitlabCiYml, "FAILED: /tmp/pipeleek-exploit-executed.txt not found")
		assert.Contains(t, gitlabCiYml, "Checking /tmp for any proof files")
	})
}

// fileInfo tracks file creation details
type fileInfo struct {
	content    string
	executable bool
}

// createMockGitLabServer creates a mock GitLab API server that captures file creation requests
func createMockGitLabServer(createdFiles map[string]fileInfo) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/projects"):
			// Create project
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":123,"name":"test-repo","web_url":"https://gitlab.example.com/test/test-repo"}`))

		case r.Method == "POST" && strings.Contains(r.URL.Path, "/repository/files/"):
			// Create file - extract filename from URL (URL encoded)
			parts := strings.Split(r.URL.Path, "/repository/files/")
			if len(parts) == 2 {
				// Decode URL-encoded filename
				encodedFilename := parts[1]
				decodedFilename, err := url.PathUnescape(encodedFilename)
				if err != nil {
					decodedFilename = encodedFilename
				}

				// Parse request body to get content and executable flag
				var reqBody struct {
					Content         string `json:"content"`
					ExecuteFilemode bool   `json:"execute_filemode"`
				}
				if err := decodeJSON(r.Body, &reqBody); err == nil {
					createdFiles[decodedFilename] = fileInfo{
						content:    reqBody.Content,
						executable: reqBody.ExecuteFilemode,
					}
				}
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"file_path":"test.txt","branch":"main"}`))

		case r.Method == "POST" && strings.Contains(r.URL.Path, "/members"):
			// Add member
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":456,"access_level":30}`))

		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
}

// decodeJSON is a helper to decode JSON from request body
func decodeJSON(body io.Reader, v interface{}) error {
	data, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func TestRunGenerate_FilesCreated(t *testing.T) {
	createdFiles := make(map[string]fileInfo)
	server := createMockGitLabServer(createdFiles)
	defer server.Close()

	// Call RunGenerate with mock server (without CI/CD and without username to avoid invite)
	RunGenerate(server.URL, "test-token", "test-repo", "", false)

	// Verify all expected files were created
	expectedFiles := map[string]struct {
		contentCheck func(string) bool
		executable   bool
	}{
		"renovate.json": {
			contentCheck: func(c string) bool { return strings.Contains(c, `"$schema"`) },
			executable:   false,
		},
		"build.gradle": {
			contentCheck: func(c string) bool { return strings.Contains(c, "plugins") },
			executable:   false,
		},
		"gradlew": {
			contentCheck: func(c string) bool { return strings.Contains(c, "#!/bin/sh") },
			executable:   true,
		},
		"gradle/wrapper/gradle-wrapper.properties": {
			contentCheck: func(c string) bool { return strings.Contains(c, "distributionUrl") },
			executable:   false,
		},
		"exploit.sh": {
			contentCheck: func(c string) bool { return strings.Contains(c, "#!/bin/sh") },
			executable:   true,
		},
	}

	for filename, expected := range expectedFiles {
		t.Run("creates "+filename, func(t *testing.T) {
			file, exists := createdFiles[filename]
			assert.True(t, exists, "File %s should be created", filename)
			if exists {
				assert.True(t, expected.contentCheck(file.content), "File %s should have expected content", filename)
				assert.Equal(t, expected.executable, file.executable, "File %s executable flag should be %v", filename, expected.executable)
			}
		})
	}

	// Verify correct number of files created (without CI/CD)
	assert.Equal(t, 5, len(createdFiles), "Should create exactly 5 files without CI/CD option")
}

func TestRunGenerate_WithCICD(t *testing.T) {
	createdFiles := make(map[string]fileInfo)
	server := createMockGitLabServer(createdFiles)
	defer server.Close()

	// Call RunGenerate with CI/CD option enabled
	RunGenerate(server.URL, "test-token", "test-repo", "", true)

	// Verify .gitlab-ci.yml was created
	t.Run("creates .gitlab-ci.yml", func(t *testing.T) {
		file, exists := createdFiles[".gitlab-ci.yml"]
		assert.True(t, exists, ".gitlab-ci.yml should be created when addRenovateCICD is true")
		if exists {
			assert.Contains(t, file.content, "renovate", "CI file should contain renovate configuration")
			assert.False(t, file.executable, ".gitlab-ci.yml should not be executable")
		}
	})

	// Verify correct number of files created (with CI/CD)
	assert.Equal(t, 6, len(createdFiles), "Should create exactly 6 files with CI/CD option")
}

func TestFileContents_Security(t *testing.T) {
	t.Run("exploit script does not contain actual credentials", func(t *testing.T) {
		assert.NotContains(t, pkgrenovate.ExploitScript, "password")
		assert.NotContains(t, pkgrenovate.ExploitScript, "secret_key")
		assert.NotContains(t, pkgrenovate.ExploitScript, "api_token")
	})

	t.Run("gradlew script does not leak information", func(t *testing.T) {
		assert.NotContains(t, pkgrenovate.GradlewScript, "password")
		assert.NotContains(t, pkgrenovate.GradlewScript, "http://", "Should not contain hardcoded URLs")
		assert.NotContains(t, pkgrenovate.GradlewScript, "https://", "Should not contain hardcoded URLs")
	})

	t.Run("no hardcoded attacker infrastructure in defaults", func(t *testing.T) {
		// The exploit script should have examples commented out
		lines := strings.Split(pkgrenovate.ExploitScript, "\n")
		for _, line := range lines {
			if strings.Contains(line, "http") && !strings.HasPrefix(strings.TrimSpace(line), "#") {
				t.Errorf("Found uncommented URL in exploit script: %s", line)
			}
		}
	})
}

func TestExploitMechanism(t *testing.T) {
	t.Run("requires outdated gradle version", func(t *testing.T) {
		assert.Contains(t, pkgrenovate.GradleWrapperProperties, "gradle-7.0")
	})

	t.Run("malicious gradlew is marked executable", func(t *testing.T) {
		// This would be tested in the actual RunGenerate function
		// where createFile is called with executable=true for gradlew
		assert.Contains(t, pkgrenovate.GradlewScript, "#!/bin/sh", "Script must have shebang to be executable")
	})

	t.Run("exploit.sh is marked executable", func(t *testing.T) {
		assert.Contains(t, pkgrenovate.ExploitScript, "#!/bin/sh", "Script must have shebang to be executable")
	})

	t.Run("exploitation chain is complete", func(t *testing.T) {
		// Verify the exploitation chain:
		// 1. gradle-wrapper.properties triggers Renovate to update wrapper
		assert.Contains(t, pkgrenovate.GradleWrapperProperties, "gradle-7.0")

		// 2. Renovate executes ./gradlew wrapper
		// 3. Our malicious gradlew executes exploit.sh
		assert.Contains(t, pkgrenovate.GradlewScript, "sh exploit.sh")

		// 4. exploit.sh creates proof file
		assert.Contains(t, pkgrenovate.ExploitScript, "/tmp/pipeleek-exploit-executed.txt")

		// 5. CI verification finds the proof file
		assert.Contains(t, gitlabCiYml, "/tmp/pipeleek-exploit-executed.txt")
	})
}

func TestFileNaming(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		content  string
	}{
		{"renovate config", "renovate.json", pkgrenovate.RenovateJSON},
		{"gradle build file", "build.gradle", pkgrenovate.BuildGradle},
		{"gradle wrapper script", "gradlew", pkgrenovate.GradlewScript},
		{"gradle wrapper properties", "gradle/wrapper/gradle-wrapper.properties", pkgrenovate.GradleWrapperProperties},
		{"exploit script", "exploit.sh", pkgrenovate.ExploitScript},
		{"ci configuration", ".gitlab-ci.yml", gitlabCiYml},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotEmpty(t, tt.content, "File content should not be empty")
			assert.Greater(t, len(tt.content), 10, "File content should have substantial content")
		})
	}
}

func TestExploitDocumentation(t *testing.T) {
	t.Run("gitlabCiYml has clear instructions", func(t *testing.T) {
		// Verify comprehensive setup instructions
		requiredSteps := []string{
			"Setup instructions:",
			"Project Settings",
			"Access Tokens",
			"api",
			"Maintainer",
			"CI/CD",
			"Variables",
			"RENOVATE_TOKEN",
		}

		for _, step := range requiredSteps {
			assert.Contains(t, gitlabCiYml, step, "Missing important setup step: %s", step)
		}
	})

	t.Run("exploit script explains what to replace", func(t *testing.T) {
		assert.Contains(t, pkgrenovate.ExploitScript, "Replace this with your actual exploit code")
		assert.Contains(t, pkgrenovate.ExploitScript, "Examples:")
	})

	t.Run("comments explain the attack mechanism", func(t *testing.T) {
		assert.Contains(t, pkgrenovate.GradlewScript, "Malicious Gradle wrapper")
		assert.Contains(t, pkgrenovate.GradlewScript, "Renovate")
		assert.Contains(t, pkgrenovate.GradlewScript, "artifact update phase")
	})
}

func TestLogMessages(t *testing.T) {
	// These tests verify that informative log messages are present
	// The actual logging would be tested in integration tests

	t.Run("mentions gradle wrapper mechanism", func(t *testing.T) {
		// This would be checked in the RunGenerate function logs
		// For now, verify our template variables contain the right info
		assert.Contains(t, pkgrenovate.GradlewScript, "Gradle wrapper")
	})

	t.Run("warns about retest procedures", func(t *testing.T) {
		assert.Contains(t, gitlabCiYml, "# This verifies the exploit")
	})
}

func TestContentQuality(t *testing.T) {
	t.Run("all content is non-empty", func(t *testing.T) {
		contents := map[string]string{
			"pkgrenovate.RenovateJSON":            pkgrenovate.RenovateJSON,
			"pkgrenovate.BuildGradle":             pkgrenovate.BuildGradle,
			"pkgrenovate.GradlewScript":           pkgrenovate.GradlewScript,
			"pkgrenovate.GradleWrapperProperties": pkgrenovate.GradleWrapperProperties,
			"pkgrenovate.ExploitScript":           pkgrenovate.ExploitScript,
			"gitlabCiYml":             gitlabCiYml,
		}

		for name, content := range contents {
			assert.NotEmpty(t, content, "%s should not be empty", name)
			assert.Greater(t, len(strings.TrimSpace(content)), 20,
				"%s should have substantial content", name)
		}
	})

	t.Run("scripts have proper line endings", func(t *testing.T) {
		scripts := []string{pkgrenovate.GradlewScript, pkgrenovate.ExploitScript}
		for _, script := range scripts {
			// Should use Unix line endings
			assert.NotContains(t, script, "\r\n", "Scripts should use Unix line endings")
		}
	})
}
