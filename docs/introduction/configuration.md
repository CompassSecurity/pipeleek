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
  trufflehog_verification: true
  max_artifact_size: 100Mb
  confidence_filter: medium # low, medium, high, high-verified
  hit_timeout: 120 # Seconds
```

Override per-command:

```yaml
gitlab:
  scan:
    threads: 20 # Override common.threads for gl scan
```

## Environment Variables

Set any config key using `PIPELEEK_` prefix. Replace dots with underscores:

```bash
export PIPELEEK_GITLAB_URL=https://gitlab.example.com
export PIPELEEK_GITLAB_TOKEN=glpat-xxxxxxxxxxxxxxxxxxxx
export PIPELEEK_GITLAB_ENUM_LEVEL=full

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
  trufflehog_verification: false
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
pipeleek config set common.trufflehog_verification false

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

Pipeleek uses a single shared HTTP client across all platforms. The following global flags control its behaviour:

| Flag | Default | Description |
|---|---|---|
| `--insecure-skip-verify` | `true` | Skip TLS certificate verification. Set to `false` to enforce certificate validation (e.g. in production environments). |
| `--ignore-proxy` | `false` | Ignore the `HTTP_PROXY` environment variable. |
| `--socks-proxy <url>` | _(none)_ | SOCKS proxy URL (e.g. `socks5://127.0.0.1:1080`). Takes precedence over `HTTP_PROXY`. |
| `--http-timeout <duration>` | _(no timeout)_ | Per-request HTTP timeout (e.g. `30s`, `2m`). |

These flags apply to all platform commands. The scope of each flag differs slightly by platform:

- `--insecure-skip-verify`, `--socks-proxy`, and `--ignore-proxy` apply to **all** platforms (GitLab, Gitea, Jenkins, Bitbucket, Azure DevOps, CircleCI, NIST, rule downloads, etc.) via the shared transport.
- `--http-timeout` applies to platforms that use the **retryable HTTP client** (GitLab, Gitea, Jenkins, CircleCI, NIST, and rule downloads). Bitbucket and Azure DevOps use Resty with a transport-only injection and are unaffected by this flag; configure their timeouts via Resty's own settings if needed.

> **Note:** The GitHub SDK client uses a dedicated rate-limit transport (`go-github-ratelimit`) that cannot be replaced. TLS and proxy settings from `--insecure-skip-verify` / `--socks-proxy` are applied to all other platforms only.

### Examples

```bash
# Enforce TLS certificate validation
pipeleek --insecure-skip-verify=false gl scan --token glpat-xxx --url https://gitlab.example.com

# Route all traffic through a SOCKS5 proxy
pipeleek --socks-proxy socks5://127.0.0.1:1080 gl scan --token glpat-xxx --url https://gitlab.example.com

# Ignore HTTP_PROXY and use a 30-second per-request timeout
pipeleek --ignore-proxy --http-timeout 30s gl scan --token glpat-xxx --url https://gitlab.example.com
```
