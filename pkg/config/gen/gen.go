// Package gen provides functionality to generate the example pipeleek configuration file.
// The generated output reflects the actual Viper defaults and flag-to-key mappings used by each command.
package gen

// ExampleConfig is the canonical template for pipeleek.example.yaml.
// It is generated from the actual defaults in pkg/config/loader.go setDefaults()
// and the flag-to-Viper-key mappings registered in each command's AutoBindFlags call.
const ExampleConfig = `# Pipeleek Configuration File (YAML)
#
# This file provides a comprehensive template for configuring Pipeleek.
# Configuration values can be provided via:
#   1. CLI flags (highest priority)
#   2. Environment variables (PIPELEEK_* prefix, e.g., PIPELEEK_GITLAB_TOKEN)
#   3. Configuration file (this file)
#   4. Defaults (lowest priority)
#
# Schema: <platform>.<subcommand>.<flag_name>
#   - Flag names with dashes are converted to underscores (e.g., --max-artifact-size -> max_artifact_size)
#   - Platform-level settings (url, token) can be shared across subcommands
#   - Command-specific settings override platform defaults
#
# Copy this file to one of these locations:
#   - ~/.config/pipeleek/pipeleek.yaml (recommended)
#   - ~/pipeleek.yaml
#   - ./pipeleek.yaml (current directory)
# Or specify explicitly: pipeleek --config /path/to/config.yaml

# Common settings applied across all platforms (primarily for scan commands)
common:
  threads: 4                    # --threads | PIPELEEK_COMMON_THREADS
  trufflehog_verification: true # --truffle-hog-verification | PIPELEEK_COMMON_TRUFFLEHOG_VERIFICATION
  max_artifact_size: "500Mb"    # --max-artifact-size | PIPELEEK_COMMON_MAX_ARTIFACT_SIZE
  confidence_filter: []         # --confidence | PIPELEEK_COMMON_CONFIDENCE_FILTER (values: low, medium, high, high-verified)
  hit_timeout: "60s"            # --hit-timeout | PIPELEEK_COMMON_HIT_TIMEOUT

#------------------------------------------------------------------------------
# GitLab Platform Configuration
#------------------------------------------------------------------------------
gitlab:
  # Platform-wide settings (shared across all GitLab commands)
  url: https://gitlab.example.com    # --gitlab | PIPELEEK_GITLAB_URL
  token: glpat-REPLACE_ME           # --token | PIPELEEK_GITLAB_TOKEN
  cookie: ""                        # --cookie (optional, _gitlab_session for dotenv artifacts)

  # enum - Enumerate token access rights
  enum:
    level: "full"                   # --level | PIPELEEK_GITLAB_ENUM_LEVEL (values: minimal, full)

  # cicd yaml - Dump CI/CD YAML configuration
  cicd:
    yaml:
      project: "group/project"      # --project | PIPELEEK_GITLAB_CICD_YAML_PROJECT

  # schedule - Enumerate scheduled pipelines (inherits gitlab.url and gitlab.token)
  schedule: {}

  # secureFiles - Print CI/CD secure files (inherits gitlab.url and gitlab.token)
  secureFiles: {}

  # variables - Print CI/CD variables (inherits gitlab.url and gitlab.token)
  variables: {}

  # jobToken exploit - Validate job token and attempt repo write
  jobToken:
    exploit:
      project: "group/project"      # --project | PIPELEEK_GITLAB_JOBTOKEN_EXPLOIT_PROJECT

  # vuln - Check GitLab version vulnerabilities (inherits gitlab.url and gitlab.token)
  vuln: {}

  # runners list - List available runners (inherits gitlab.url and gitlab.token)
  runners:
    list: {}

    # runners exploit - Create exploit project for runners
    exploit:
      tags: []                      # --tags | PIPELEEK_GITLAB_RUNNERS_EXPLOIT_TAGS
      dry: false                    # --dry | PIPELEEK_GITLAB_RUNNERS_EXPLOIT_DRY
      shell: "bash"                 # --shell | PIPELEEK_GITLAB_RUNNERS_EXPLOIT_SHELL (values: bash, powershell, pwsh)
      age_public_key: ""            # --age-public-key | PIPELEEK_GITLAB_RUNNERS_EXPLOIT_AGE_PUBLIC_KEY
      repo_name: ""                 # --repo-name | PIPELEEK_GITLAB_RUNNERS_EXPLOIT_REPO_NAME

  # renovate - Renovate bot commands
  renovate:
    # enum - Enumerate Renovate bot configurations
    enum:
      owned: true                                  # --owned | PIPELEEK_GITLAB_RENOVATE_ENUM_OWNED
      member: true                                 # --member | PIPELEEK_GITLAB_RENOVATE_ENUM_MEMBER
      repo: false                                  # --repo | PIPELEEK_GITLAB_RENOVATE_ENUM_REPO
      namespace: false                             # --namespace | PIPELEEK_GITLAB_RENOVATE_ENUM_NAMESPACE
      search: ""                                   # --search | PIPELEEK_GITLAB_RENOVATE_ENUM_SEARCH
      fast: false                                  # --fast | PIPELEEK_GITLAB_RENOVATE_ENUM_FAST
      dump: false                                  # --dump | PIPELEEK_GITLAB_RENOVATE_ENUM_DUMP
      page: 1                                      # --page | PIPELEEK_GITLAB_RENOVATE_ENUM_PAGE
      order_by: "last_activity_at"                 # --order-by | PIPELEEK_GITLAB_RENOVATE_ENUM_ORDER_BY
      extend_renovate_config_service: ""           # --extend-renovate-config-service | PIPELEEK_GITLAB_RENOVATE_ENUM_EXTEND_RENOVATE_CONFIG_SERVICE

    bots:
      term: "renovate"              # --term | PIPELEEK_GITLAB_RENOVATE_BOTS_TERM

    autodiscovery:
      repo_name: ""                 # --repo-name | PIPELEEK_GITLAB_RENOVATE_AUTODISCOVERY_REPO_NAME
      username: ""                  # --username | PIPELEEK_GITLAB_RENOVATE_AUTODISCOVERY_USERNAME
      add_renovate_cicd_for_debugging: false  # --add-renovate-cicd-for-debugging | PIPELEEK_GITLAB_RENOVATE_AUTODISCOVERY_ADD_RENOVATE_CICD_FOR_DEBUGGING

    privesc:
      repo_name: ""                 # --repo-name | PIPELEEK_GITLAB_RENOVATE_PRIVESC_REPO_NAME

  # register - Register new user account
  register:
    username: "newuser"             # --username | PIPELEEK_GITLAB_REGISTER_USERNAME
    password: "securepassword"      # --password | PIPELEEK_GITLAB_REGISTER_PASSWORD
    email: "newuser@example.com"    # --email | PIPELEEK_GITLAB_REGISTER_EMAIL

  # shodan - Query Shodan for GitLab instances
  shodan:
    json: "shodan_data.json"        # --json | PIPELEEK_GITLAB_SHODAN_JSON

  # scan_public - Scan public GitLab pipelines without an account
  scan_public:
    search: ""                      # --search | PIPELEEK_GITLAB_SCAN_PUBLIC_SEARCH
    repo: ""                        # --repo | PIPELEEK_GITLAB_SCAN_PUBLIC_REPO
    namespace: ""                   # --namespace | PIPELEEK_GITLAB_SCAN_PUBLIC_NAMESPACE
    job_limit: 0                    # --job-limit | PIPELEEK_GITLAB_SCAN_PUBLIC_JOB_LIMIT
    queue: ""                       # --queue | PIPELEEK_GITLAB_SCAN_PUBLIC_QUEUE
    artifacts: false                # --artifacts | PIPELEEK_GITLAB_SCAN_PUBLIC_ARTIFACTS

  # scan - Scan CI/CD artifacts for secrets
  scan:
    search: ""                      # --search | PIPELEEK_GITLAB_SCAN_SEARCH
    member: false                   # --member | PIPELEEK_GITLAB_SCAN_MEMBER
    repo: ""                        # --repo | PIPELEEK_GITLAB_SCAN_REPO
    namespace: ""                   # --namespace | PIPELEEK_GITLAB_SCAN_NAMESPACE
    job_limit: 0                    # --job-limit | PIPELEEK_GITLAB_SCAN_JOB_LIMIT
    queue: ""                       # --queue | PIPELEEK_GITLAB_SCAN_QUEUE
    artifacts: false                # --artifacts | PIPELEEK_GITLAB_SCAN_ARTIFACTS
    owned: false                    # --owned | PIPELEEK_GITLAB_SCAN_OWNED
    # Inherits common.* settings (threads, trufflehog_verification, max_artifact_size, confidence_filter, hit_timeout)

  # snippets scan - Scan snippets for secrets
  snippets:
    scan:
      project: ""                   # --project | PIPELEEK_GITLAB_SNIPPETS_SCAN_PROJECT
      namespace: ""                 # --namespace | PIPELEEK_GITLAB_SNIPPETS_SCAN_NAMESPACE
      search: ""                    # --search | PIPELEEK_GITLAB_SNIPPETS_SCAN_SEARCH
      owned: false                  # --owned | PIPELEEK_GITLAB_SNIPPETS_SCAN_OWNED
      member: false                 # --member | PIPELEEK_GITLAB_SNIPPETS_SCAN_MEMBER
      # Inherits common.* settings

  # tf - Discover and scan Terraform/OpenTofu state files
  tf:
    output_dir: "./terraform-states" # --output-dir | PIPELEEK_GITLAB_TF_OUTPUT_DIR
    threads: 4                       # --threads | PIPELEEK_GITLAB_TF_THREADS

#------------------------------------------------------------------------------
# GitHub Platform Configuration
#------------------------------------------------------------------------------
github:
  url: https://api.github.com    # --github | PIPELEEK_GITHUB_URL
  token: ghp_REPLACE_ME          # --token | PIPELEEK_GITHUB_TOKEN

  # ghtoken exploit - Validate GitHub Actions token and attempt repo clone
  ghtoken:
    exploit:
      repo: "owner/repo"         # --repo | PIPELEEK_GITHUB_GHTOKEN_EXPLOIT_REPO

  # scan - Scan GitHub Actions artifacts for secrets
  scan:
    org: ""                      # --org | PIPELEEK_GITHUB_SCAN_ORG
    user: ""                     # --user | PIPELEEK_GITHUB_SCAN_USER
    search: ""                   # --search | PIPELEEK_GITHUB_SCAN_SEARCH
    repo: ""                     # --repo | PIPELEEK_GITHUB_SCAN_REPO
    public: false                # --public | PIPELEEK_GITHUB_SCAN_PUBLIC
    max_workflows: 0             # --max-workflows | PIPELEEK_GITHUB_SCAN_MAX_WORKFLOWS (0 = no limit)
    artifacts: false             # --artifacts | PIPELEEK_GITHUB_SCAN_ARTIFACTS
    owned: false                 # --owned | PIPELEEK_GITHUB_SCAN_OWNED
    # Inherits common.* settings

  # renovate - Renovate bot commands
  renovate:
    enum:
      owned: true                # --owned | PIPELEEK_GITHUB_RENOVATE_ENUM_OWNED
      member: true               # --member | PIPELEEK_GITHUB_RENOVATE_ENUM_MEMBER
      search: ""                 # --search | PIPELEEK_GITHUB_RENOVATE_ENUM_SEARCH
      fast: false                # --fast | PIPELEEK_GITHUB_RENOVATE_ENUM_FAST
      dump: false                # --dump | PIPELEEK_GITHUB_RENOVATE_ENUM_DUMP

    autodiscovery:
      repo_name: ""              # --repo-name | PIPELEEK_GITHUB_RENOVATE_AUTODISCOVERY_REPO_NAME

    privesc:
      repo_name: ""              # --repo-name | PIPELEEK_GITHUB_RENOVATE_PRIVESC_REPO_NAME

#------------------------------------------------------------------------------
# BitBucket Platform Configuration
#------------------------------------------------------------------------------
bitbucket:
  url: https://api.bitbucket.org/2.0  # --bitbucket | PIPELEEK_BITBUCKET_URL
  email: user@example.com             # --email | PIPELEEK_BITBUCKET_EMAIL
  token: ATATTxxxxxx                  # --token | PIPELEEK_BITBUCKET_TOKEN
  cookie: ""                          # --cookie | PIPELEEK_BITBUCKET_COOKIE (cloud.session.token for artifact scanning)

  # scan - Scan BitBucket Pipelines artifacts
  scan:
    workspace: ""                     # --workspace | PIPELEEK_BITBUCKET_SCAN_WORKSPACE
    max_pipelines: 0                  # --max-pipelines | PIPELEEK_BITBUCKET_SCAN_MAX_PIPELINES (0 = no limit)
    public: false                     # --public | PIPELEEK_BITBUCKET_SCAN_PUBLIC
    after: ""                         # --after | PIPELEEK_BITBUCKET_SCAN_AFTER (ISO 8601 format)
    artifacts: false                  # --artifacts | PIPELEEK_BITBUCKET_SCAN_ARTIFACTS
    owned: false                      # --owned | PIPELEEK_BITBUCKET_SCAN_OWNED
    # Inherits common.* settings

#------------------------------------------------------------------------------
# Azure DevOps Configuration
#------------------------------------------------------------------------------
azure_devops:
  url: https://dev.azure.com    # --devops | PIPELEEK_AZURE_DEVOPS_URL
  token: ado_pat_REPLACE_ME     # --token | PIPELEEK_AZURE_DEVOPS_TOKEN
  username: ""                  # --username | PIPELEEK_AZURE_DEVOPS_USERNAME

  # scan - Scan Azure Pipelines artifacts
  scan:
    organization: ""            # --organization | PIPELEEK_AZURE_DEVOPS_SCAN_ORGANIZATION
    project: ""                 # --project | PIPELEEK_AZURE_DEVOPS_SCAN_PROJECT
    max_builds: 0               # --max-builds | PIPELEEK_AZURE_DEVOPS_SCAN_MAX_BUILDS (0 = no limit)
    artifacts: false            # --artifacts | PIPELEEK_AZURE_DEVOPS_SCAN_ARTIFACTS
    owned: false                # --owned | PIPELEEK_AZURE_DEVOPS_SCAN_OWNED
    # Inherits common.* settings

#------------------------------------------------------------------------------
# Gitea Platform Configuration
#------------------------------------------------------------------------------
gitea:
  url: https://gitea.example.com    # --gitea | PIPELEEK_GITEA_URL
  token: gitea_pat_REPLACE_ME       # --token | PIPELEEK_GITEA_TOKEN

  # enum - Enumerate token access rights (inherits gitea.url and gitea.token)
  enum: {}

  # variables - Print repository/organization variables
  variables:
    owner: "example-org"    # --owner | PIPELEEK_GITEA_VARIABLES_OWNER
    repo: "example-repo"    # --repo | PIPELEEK_GITEA_VARIABLES_REPO

  # secrets - Print repository/organization secrets
  secrets:
    owner: "example-org"    # --owner | PIPELEEK_GITEA_SECRETS_OWNER
    repo: "example-repo"    # --repo | PIPELEEK_GITEA_SECRETS_REPO

  # vuln - Check Gitea version vulnerabilities (inherits gitea.url and gitea.token)
  vuln: {}

  # scan - Scan Gitea Actions artifacts
  scan:
    organization: ""        # --organization | PIPELEEK_GITEA_SCAN_ORGANIZATION
    repository: ""          # --repository | PIPELEEK_GITEA_SCAN_REPOSITORY
    runs_limit: 0           # --runs-limit | PIPELEEK_GITEA_SCAN_RUNS_LIMIT (0 = no limit)
    start_run_id: 0         # --start-run-id | PIPELEEK_GITEA_SCAN_START_RUN_ID
    artifacts: false        # --artifacts | PIPELEEK_GITEA_SCAN_ARTIFACTS
    owned: false            # --owned | PIPELEEK_GITEA_SCAN_OWNED
    # Inherits common.* settings

#------------------------------------------------------------------------------
# Jenkins Platform Configuration
#------------------------------------------------------------------------------
jenkins:
  url: https://jenkins.example.com    # --jenkins | PIPELEEK_JENKINS_URL
  username: admin                     # --username | PIPELEEK_JENKINS_USERNAME
  token: jenkins_api_token_REPLACE_ME # --token | PIPELEEK_JENKINS_TOKEN

  # scan - Scan Jenkins jobs, build logs, env vars, and optional artifacts
  scan:
    folder: ""             # --folder | PIPELEEK_JENKINS_SCAN_FOLDER
    job: ""                # --job | PIPELEEK_JENKINS_SCAN_JOB
    max_builds: 25         # --max-builds | PIPELEEK_JENKINS_SCAN_MAX_BUILDS (0 = all builds)
    artifacts: false       # --artifacts | PIPELEEK_JENKINS_SCAN_ARTIFACTS
    # Inherits common.* settings

#------------------------------------------------------------------------------
# CircleCI Platform Configuration
#------------------------------------------------------------------------------
circle:
  url: https://circleci.com          # --circle | PIPELEEK_CIRCLE_URL
  token: circleci_token_REPLACE_ME   # --token | PIPELEEK_CIRCLE_TOKEN

  # scan - Scan CircleCI pipelines, logs, test results and optional artifacts
  scan:
    org: ""                                    # --org | PIPELEEK_CIRCLE_SCAN_ORG
    project: []                                # --project | PIPELEEK_CIRCLE_SCAN_PROJECT (format: org/repo or vcs/org/repo)
    vcs: "github"                              # --vcs | PIPELEEK_CIRCLE_SCAN_VCS (github or bitbucket)
    branch: ""                                 # --branch | PIPELEEK_CIRCLE_SCAN_BRANCH
    status: []                                 # --status | PIPELEEK_CIRCLE_SCAN_STATUS (success, failed, etc.)
    workflow: []                               # --workflow | PIPELEEK_CIRCLE_SCAN_WORKFLOW
    job: []                                    # --job | PIPELEEK_CIRCLE_SCAN_JOB
    since: ""                                  # --since | PIPELEEK_CIRCLE_SCAN_SINCE (RFC3339 timestamp)
    until: ""                                  # --until | PIPELEEK_CIRCLE_SCAN_UNTIL (RFC3339 timestamp)
    max_pipelines: 0                           # --max-pipelines | PIPELEEK_CIRCLE_SCAN_MAX_PIPELINES (0 = no limit)
    tests: true                                # --tests | PIPELEEK_CIRCLE_SCAN_TESTS
    insights: true                             # --insights | PIPELEEK_CIRCLE_SCAN_INSIGHTS
    # Inherits common.* settings
`

// GenerateExampleConfig returns the example configuration file content.
func GenerateExampleConfig() string {
	return ExampleConfig
}
