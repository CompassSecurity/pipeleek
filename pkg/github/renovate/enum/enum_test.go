package renovate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseWorkflowYAML(t *testing.T) {
	tests := []struct {
		name        string
		yamlContent string
		wantErr     bool
		checkResult func(*testing.T, map[string]interface{})
	}{
		{
			name: "parses valid workflow YAML",
			yamlContent: `name: CI
on:
  push:
    branches:
      - main
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2`,
			wantErr: false,
			checkResult: func(t *testing.T, result map[string]interface{}) {
				assert.Equal(t, "CI", result["name"])
				assert.NotNil(t, result["on"])
				assert.NotNil(t, result["jobs"])
			},
		},
		{
			name: "parses renovate workflow",
			yamlContent: `name: Renovate
on:
  schedule:
    - cron: '0 0 * * *'
jobs:
  renovate:
    runs-on: ubuntu-latest
    steps:
      - uses: renovatebot/renovate@v1
        env:
          RENOVATE_TOKEN: ${{ secrets.RENOVATE_TOKEN }}`,
			wantErr: false,
			checkResult: func(t *testing.T, result map[string]interface{}) {
				assert.Equal(t, "Renovate", result["name"])
				jobs, ok := result["jobs"].(map[string]interface{})
				require.True(t, ok)
				assert.Contains(t, jobs, "renovate")
			},
		},
		{
			name:        "handles empty YAML",
			yamlContent: "",
			wantErr:     false,
			checkResult: func(t *testing.T, result map[string]interface{}) {
				assert.Nil(t, result)
			},
		},
		{
			name:        "returns error for invalid YAML",
			yamlContent: "invalid:\n  - yaml\n    content: [unclosed",
			wantErr:     true,
			checkResult: nil,
		},
		{
			name: "parses complex nested structure",
			yamlContent: `name: Complex
on:
  push:
  pull_request:
    types: [opened, synchronize]
env:
  NODE_VERSION: 18
  RENOVATE_AUTODISCOVER: true
  RENOVATE_AUTODISCOVER_FILTER: ${{ github.repository }}
jobs:
  renovate:
    runs-on: ubuntu-latest
    container:
      image: renovate/renovate:latest
    steps:
      - run: echo "test"`,
			wantErr: false,
			checkResult: func(t *testing.T, result map[string]interface{}) {
				assert.Equal(t, "Complex", result["name"])
				env, ok := result["env"].(map[string]interface{})
				require.True(t, ok)
				assert.Equal(t, 18, env["NODE_VERSION"])
				assert.Equal(t, true, env["RENOVATE_AUTODISCOVER"])
			},
		},
		{
			name: "handles workflow with multiple jobs",
			yamlContent: `name: Multi-Job
jobs:
  test:
    runs-on: ubuntu-latest
  build:
    runs-on: ubuntu-latest
  deploy:
    runs-on: ubuntu-latest`,
			wantErr: false,
			checkResult: func(t *testing.T, result map[string]interface{}) {
				jobs, ok := result["jobs"].(map[string]interface{})
				require.True(t, ok)
				assert.Len(t, jobs, 3)
				assert.Contains(t, jobs, "test")
				assert.Contains(t, jobs, "build")
				assert.Contains(t, jobs, "deploy")
			},
		},
		{
			name: "parses workflow with strategy matrix",
			yamlContent: `name: Matrix
jobs:
  test:
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
        node: [14, 16, 18]`,
			wantErr: false,
			checkResult: func(t *testing.T, result map[string]interface{}) {
				jobs, ok := result["jobs"].(map[string]interface{})
				require.True(t, ok)
				test, ok := jobs["test"].(map[string]interface{})
				require.True(t, ok)
				strategy, ok := test["strategy"].(map[string]interface{})
				require.True(t, ok)
				assert.Contains(t, strategy, "matrix")
			},
		},
		{
			name: "handles anchors and aliases",
			yamlContent: `name: Anchors
defaults: &defaults
  runs-on: ubuntu-latest
jobs:
  test:
    <<: *defaults
    steps:
      - run: echo "test"`,
			wantErr: false,
			checkResult: func(t *testing.T, result map[string]interface{}) {
				assert.NotNil(t, result["jobs"])
			},
		},
		{
			name: "parses workflow with conditional expressions",
			yamlContent: `name: Conditional
jobs:
  renovate:
    if: github.event_name == 'schedule'
    runs-on: ubuntu-latest`,
			wantErr: false,
			checkResult: func(t *testing.T, result map[string]interface{}) {
				jobs, ok := result["jobs"].(map[string]interface{})
				require.True(t, ok)
				renovate, ok := jobs["renovate"].(map[string]interface{})
				require.True(t, ok)
				assert.Contains(t, renovate, "if")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseWorkflowYAML(tt.yamlContent)
			
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.checkResult != nil {
					tt.checkResult(t, result)
				}
			}
		})
	}
}

func TestParseWorkflowYAML_RealWorldExamples(t *testing.T) {
	tests := []struct {
		name        string
		yamlContent string
		description string
	}{
		{
			name: "GitHub Actions renovate with autodiscovery",
			yamlContent: `name: Renovate
on:
  workflow_dispatch:
  schedule:
    - cron: '0 * * * *'
jobs:
  renovate:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      - name: Self-hosted Renovate
        uses: renovatebot/github-action@v40
        env:
          RENOVATE_AUTODISCOVER: true
          RENOVATE_AUTODISCOVER_FILTER: ${{ github.repository }}
          LOG_LEVEL: debug`,
			description: "Real-world autodiscovery setup",
		},
		{
			name: "Renovate with Docker container",
			yamlContent: `name: Renovate
on:
  schedule:
    - cron: '0 0 * * *'
jobs:
  renovate:
    runs-on: ubuntu-latest
    container:
      image: renovate/renovate:latest
    steps:
      - run: renovate --schedule="at any time"`,
			description: "Container-based renovate",
		},
		{
			name: "Complex multi-step renovate workflow",
			yamlContent: `name: Renovate
on:
  push:
    branches: [main]
  schedule:
    - cron: '0 2 * * *'
env:
  RENOVATE_CONFIG_FILE: .github/renovate.json5
  LOG_LEVEL: info
jobs:
  renovate:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - name: Setup Node
        uses: actions/setup-node@v4
        with:
          node-version: 20
      - name: Run Renovate
        run: |
          npx renovate \
            --token="${{ secrets.GITHUB_TOKEN }}" \
            --platform=github \
            --autodiscover=true`,
			description: "Multi-step with NPX",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseWorkflowYAML(tt.yamlContent)
			assert.NoError(t, err, "Failed to parse: %s", tt.description)
			assert.NotNil(t, result)
			assert.Contains(t, result, "name")
			assert.Contains(t, result, "jobs")
		})
	}
}

func TestParseWorkflowYAML_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		yamlContent string
		wantErr     bool
	}{
		{
			name:        "handles YAML with only comments",
			yamlContent: "# Just a comment\n# Another comment",
			wantErr:     false,
		},
		{
			name:        "handles YAML with unicode characters",
			yamlContent: "name: 🚀 Deploy\njobs:\n  test:\n    runs-on: ubuntu-latest",
			wantErr:     false,
		},
		{
			name: "handles multiline strings",
			yamlContent: `name: Test
jobs:
  test:
    steps:
      - run: |
          echo "Line 1"
          echo "Line 2"
          echo "Line 3"`,
			wantErr: false,
		},
		{
			name:        "handles tabs and mixed indentation",
			yamlContent: "name: Test\njobs:\n\ttest:\n    runs-on: ubuntu-latest",
			wantErr:     true, // YAML doesn't allow tabs for indentation
		},
		{
			name: "handles numeric and boolean values",
			yamlContent: `name: Test
env:
  PORT: 8080
  ENABLED: true
  DISABLED: false
  RATIO: 3.14`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseWorkflowYAML(tt.yamlContent)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
