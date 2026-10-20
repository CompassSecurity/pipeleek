---
title: Configuration
description: Configure Pipeleek using config files, environment variables, or CLI flags
keywords:
  - pipeleek configuration
  - config file
  - credentials management
---

# Configuration

Pipeleek can be configured via config files, environment variables, or CLI flags. This eliminates repetitive flag usage, simplifies and secures credential management.

## Quick Start

Generate a configuration template with all available options:

```bash
# Write to config file (recommended)
pipeleek config gen --output ~/.config/pipeleek/pipeleek.yaml
```

The generated template documents all settings, their defaults, CLI flags, and environment variable names for quick reference.

Then configure your needed object keys, for example:

```yaml
gitlab:
  url: https://gitlab.example.com
  token: glpat-xxxxxxxxxxxxxxxxxxxx
```

Run commands without flags:

```bash
pipeleek gl enum
pipeleek gl scan
```

## Priority Order

Configuration sources are resolved in this order (highest to lowest):

1. **CLI flags** - `--url`, `--token`, etc.
2. **Environment variables** - `PIPELEEK_GITLAB_TOKEN`
3. **Config file** - `~/.config/pipeleek/pipeleek.yaml`
4. **Defaults**

## Config File Locations

Pipeleek searches these locations in order:

1. `--config /path/to/file` (explicit path)
2. `~/.config/pipeleek/pipeleek.yaml` (recommended)
3. `~/pipeleek.yaml`
4. `./pipeleek.yaml`

## Configuration Schema

Config keys follow the pattern: `<platform>.<subcommand>.<flag_name>`

Platform-level settings (like `url` and `token`) are inherited by all commands under that platform.

To view a full example of the available keys run `pipeleek config gen`.

### Common Settings

Scan commands inherit from `common`:

```yaml
common:
  threads: 2
  secrets_verification: true
  max_artifact_size: 100Mb
  confidence_filter: [verified, high] # [] includes all; also medium, low, trufflehog, custom labels
  hit_timeout: 120 # Seconds
  webui: false # Serve a local authenticated findings UI during scans
```

### Optional Rules Download

Settings for [`pipeleek rules download`](secrets_verification.md#optional-external-rules-download):

```yaml
rules:
  download:
    output: rules.yml # --output; PIPELEEK_RULES_DOWNLOAD_OUTPUT
    force: false # --force; PIPELEEK_RULES_DOWNLOAD_FORCE
```

### Per-command Overrides

```yaml
gitlab:
  scan:
    threads: 20 # Override common.threads for gl scan
    job_status: [success, failed] # Optional; default [] scans all job statuses
    pipeline_source: schedule # Optional; default "" scans all pipeline sources

gitea:
  scan:
    repo_sort: updated # alpha, created, updated, size, or id; default updated
    repo_order: desc # asc or desc; default desc
```

### GitLab Release Assets

`pipeleek gl release scan` inherits `gitlab.url`, `gitlab.token`, and the common
scan settings above. Release-specific settings live under `gitlab.release.scan`:

```yaml
gitlab:
  url: https://gitlab.example.com
  token: "[redacted]"
  release:
    scan:
      repo: group/project # Optional; mutually exclusive with namespace
      namespace: "" # Group and subgroups
      search: "" # Project search, not release-tag search
      owned: false
      member: false # Applies to global project discovery
      tag: "" # Exact tag; requires repo; cannot combine with a nonzero release_limit
      release_limit: 0 # Published releases per project, newest first; 0 means all
      include_sources: false # Also scan one generated source ZIP per release
```

`--repo` selects a project directly and takes precedence over project-list
filters. Namespace discovery applies `owned` and `search` and includes shared
projects and subgroups, matching `gl scan`. `member` applies only when neither
`repo` nor `namespace` is set.

Release scanning uses `common.max_artifact_size` (default `500Mb`) as the maximum
downloaded and expanded bytes per asset. Larger assets are reported as skipped.
`common.threads` (default `4`) bounds concurrent asset workers;
`common.hit_timeout` accepts a duration such as `60s` or an integer number of
seconds. Confidence filtering, credential verification, and the Web UI use the
same common settings as other scans.

For example:

```bash
export PIPELEEK_GITLAB_RELEASE_SCAN_RELEASE_LIMIT=5
export PIPELEEK_GITLAB_RELEASE_SCAN_INCLUDE_SOURCES=true
pipeleek gl release scan --repo group/project
```

Linked HTTP(S) assets on external hosts are scanned by default. The GitLab token
is sent only to the configured GitLab origin, never to another origin or through
a cross-origin redirect. See [release scanning](../guides/gitlab.md#secret-detection-in-release-assets)
for coverage and failure behavior.

## Environment Variables

Set any config key using `PIPELEEK_` prefix. Replace dots with underscores:

```bash
export PIPELEEK_GITLAB_URL=https://gitlab.example.com
export PIPELEEK_GITLAB_TOKEN=glpat-xxxxxxxxxxxxxxxxxxxx
export PIPELEEK_GITLAB_ENUM_LEVEL=full
export PIPELEEK_GITLAB_ENUM_USERS=true

pipeleek gl enum
```

## Examples

### Multi-Platform Setup

```yaml
gitlab:
  url: https://gitlab.company.com
  token: glpat-prod-token

github:
  url: https://api.github.com
  token: ghp-prod-token

common:
  threads: 8
  secrets_verification: false
```

```bash
pipeleek gl scan              # Uses GitLab config
pipeleek gh scan --owned      # Uses GitHub config
```

### Override Config Values

```bash
# Use config token but different URL
pipeleek gl enum --url https://gitlab-dev.company.com

# Use config URL/token but different level
pipeleek gl enum --level minimal

# Include related users from discovered groups/projects in HTML report
pipeleek gl enum --report-html enum.html --users
```

### Partial Configuration

Config file can provide some values, flags provide others:

```yaml
gitlab:
  url: https://gitlab.example.com
```

```bash
# URL from config, token from flag
pipeleek gl enum --token glpat-xxxxxxxxxxxxxxxxxxxx
```

## Managing Config Values

### Getting Config Values

Read configuration values from your config file:

```bash
# Get a specific value
pipeleek config get gitlab.token

# Get an entire section (returns YAML)
pipeleek config get gitlab

# Get a nested value
pipeleek config get gitlab.renovate.enum.fast

# Get all configuration
pipeleek config get
```

### Setting Config Values

Write configuration values to your config file:

```bash
# Set a string value
pipeleek config set gitlab.token "glpat-xxxxxxxxxxxxxxxxxxxx"

# Set a number
pipeleek config set common.threads 8

# Set a boolean
pipeleek config set common.secrets_verification false

# Set a list (YAML format)
pipeleek config set gitlab.runners.exploit.tags '[\"docker\", \"shared\"]'
```

## Full Example

Generate a complete example with all platforms and commands documented by running:

```bash
pipeleek config gen
```

## Troubleshooting

```bash
# Use trace logging to see which keys are loaded
pipeleek --log-level=trace gl enum
```

## HTTP Client Settings

See [Using Pipeleek with Proxies](proxying.md) for proxy, TLS, and timeout configuration flags.
