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

Create `~/.config/pipeleek/pipeleek.yaml`:

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

1. **CLI flags** - `--gitlab`, `--token`, etc.
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

### GitLab

```yaml
gitlab:
  url: https://gitlab.example.com # Shared across all gl commands
  token: glpat-xxxxxxxxxxxxxxxxxxxx # Shared across all gl commands
  cookie: "" # Optional: _gitlab_session cookie for dotenv artifacts

  enum:
    level: full # gl enum --level

  cicd:
    yaml:
      project: group/project # gl cicd yaml --project

  schedule: {} # gl schedule (inherits url/token)

  secureFiles: {} # gl secureFiles (inherits url/token)

  variables: {} # gl variables (inherits url/token)

  vuln: {} # gl vuln (inherits url/token)

  runners:
    list: {} # gl runners list (inherits url/token)
    
    exploit:
      tags: [docker, linux] # gl runners exploit --tags
      shell: bash # gl runners exploit --shell
      dry: false # gl runners exploit --dry
      age_public_key: "" # gl runners exploit --age-public-key
      repo_name: "" # gl runners exploit --repo-name

  renovate:
    enum:
      owned: true # gl renovate enum --owned
      member: true # gl renovate enum --member
      repo: false # gl renovate enum --repo
      namespace: false # gl renovate enum --namespace
      search: "" # gl renovate enum --search
      fast: false # gl renovate enum --fast
      dump: false # gl renovate enum --dump
    
    autodiscovery: {} # gl renovate autodiscovery (inherits url/token)
    
    privesc: {} # gl renovate privesc (inherits url/token)

  register:
    username: newuser # gl register --username
    password: secret # gl register --password
    email: user@example.com # gl register --email

  shodan:
    json: shodan_data.json # gl shodan --json

  scan:
    threads: 10 # gl scan --threads (can override common.threads)
```

### GitHub

```yaml
github:
  url: https://api.github.com
  token: ghp_xxxxxxxxxxxxxxxxxxxx

  scan:
    owner: myorg
    repo: myrepo
```

### BitBucket

```yaml
bitbucket:
  url: https://bitbucket.org
  email: user@example.com
  token: ATATTxxxxxx

  scan:
    workspace: myworkspace
    repo_slug: myrepo
```

### Azure DevOps

```yaml
azure_devops:
  url: https://dev.azure.com/myorg
  token: ado-token

  scan:
    project: myproject
```

### Gitea

```yaml
gitea:
  url: https://gitea.example.com
  token: gitea-token

  enum:
    owner: myorg # gitea enum --owner

  secrets:
    owner: myorg # gitea secrets --owner
    repo: myrepo # gitea secrets --repo

  variables:
    owner: myorg # gitea variables --owner
    repo: myrepo # gitea variables --repo

  scan:
    owner: myorg # gitea scan --owner
    repo: myrepo # gitea scan --repo (optional, scans all if not specified)
```

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
pipeleek gl enum --gitlab https://gitlab-dev.company.com

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

## Full Example

See [`pipeleek.example.yaml`](https://github.com/CompassSecurity/pipeleek/blob/main/pipeleek.example.yaml) for a complete example with all platforms and commands documented.

## Troubleshooting

```bash
# Use trace logging to see which keys are loaded
pipeleek --log-level=trace gl enum
```
