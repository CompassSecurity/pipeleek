---
title: Configuration File
description: Learn how to use configuration files to manage credentials and settings for Pipeleek
keywords:
  - pipeleek configuration
  - config file
  - credentials management
  - yaml config
---

## Configuration File

Pipeleek supports loading configuration from YAML, JSON, or TOML files. This is useful for:

- Managing credentials for multiple platforms
- Avoiding long command lines
- Storing commonly used settings
- Securely managing secrets (when combined with file permissions)

### Priority Order

Configuration values are resolved with the following priority (highest to lowest):

1. **Command-line flags** - Values explicitly set via CLI flags
2. **Configuration file** - Values loaded from a config file
3. **Default values** - Built-in defaults

This means you can set defaults in a config file and override them with flags when needed.

### Configuration File Locations

Pipeleek searches for configuration files in the following locations (in order):

1. Path specified with `--config` flag
2. `~/.config/pipeleek/config.yaml` (recommended)
3. `~/.pipeleek.yaml`
4. `./pipeleek.yaml` (current directory)

You can also explicitly specify a config file:

```bash
pipeleek --config /path/to/config.yaml gl scan
```

### Configuration Structure

Here's a complete example configuration file with all available options:

```yaml
# GitLab Configuration
gitlab:
  url: https://gitlab.com
  token: glpat-xxxxxxxxxxxxxxxxxxxx
  # Optional: GitLab session cookie for accessing dotenv artifacts
  cookie: ""

# GitHub Configuration
github:
  url: https://api.github.com
  token: ghp_xxxxxxxxxxxxxxxxxxxx

# BitBucket Configuration
bitbucket:
  url: https://bitbucket.org
  username: your-username
  password: your-app-password

# Azure DevOps Configuration
azure_devops:
  url: https://dev.azure.com/your-organization
  token: your-pat-token

# Gitea Configuration
gitea:
  url: https://gitea.example.com
  token: your-gitea-token

# Common Settings (applied to all platforms)
common:
  # Number of concurrent threads for scanning (1-100)
  threads: 4
  
  # Enable TruffleHog credential verification
  trufflehog_verification: true
  
  # Maximum artifact size to scan
  max_artifact_size: "500Mb"
  
  # Filter results by confidence level
  # Options: low, medium, high, high-verified
  confidence_filter:
    - high
    - medium
  
  # Maximum time to wait for hit detection per scan item
  hit_timeout: "60s"
```

### Example: Simple GitLab Configuration

Create a file at `~/.config/pipeleek/config.yaml`:

```yaml
gitlab:
  url: https://gitlab.example.com
  token: glpat-mytoken123

common:
  threads: 8
  trufflehog_verification: false
```

Now you can run commands without specifying these values:

```bash
# Without config file (verbose)
pipeleek gl scan --gitlab https://gitlab.example.com --token glpat-mytoken123 --threads 8

# With config file (simplified)
pipeleek gl scan
```

### Example: Override Config Values

You can override config file values with command-line flags:

```bash
# Use config file token but different URL
pipeleek gl scan --gitlab https://gitlab-dev.example.com

# Use config file URL but different token
pipeleek gl scan --token glpat-differenttoken

# Override thread count from config
pipeleek gl scan --threads 16
```

### Example: Multi-Platform Configuration

Store credentials for multiple platforms in one file:

```yaml
gitlab:
  url: https://gitlab.example.com
  token: glpat-mytoken123

github:
  url: https://api.github.com
  token: ghp_mytoken456

bitbucket:
  url: https://bitbucket.org
  username: myuser
  password: mypassword

common:
  threads: 8
  max_artifact_size: "1GB"
  confidence_filter:
    - high
    - high-verified
```

Then switch between platforms easily:

```bash
pipeleek gl scan              # Uses GitLab credentials from config
pipeleek gh scan --owned      # Uses GitHub credentials from config
pipeleek bb scan --workspace myworkspace  # Uses BitBucket credentials from config
```

### Security Considerations

When using configuration files to store credentials:

1. **File Permissions**: Restrict access to your config file:
   ```bash
   chmod 600 ~/.config/pipeleek/config.yaml
   ```

2. **Git Ignore**: Never commit config files with credentials to version control. Add to `.gitignore`:
   ```
   pipeleek.yaml
   .pipeleek.yaml
   config.yaml
   ```

3. **Environment Variables**: For CI/CD or shared environments, use environment variables with the `PIPELEEK_` prefix:
   ```bash
   export PIPELEEK_GITLAB_TOKEN="glpat-xxxxxxxxxxxxxxxxxxxx"
   export PIPELEEK_GITLAB_URL="https://gitlab.example.com"
   ```

4. **Secret Management**: Consider using:
   - OS keychain integration
   - Secret management tools (HashiCorp Vault, AWS Secrets Manager, etc.)
   - Encrypted configuration files

### Environment Variables

All configuration values can be set via environment variables with the `PIPELEEK_` prefix:

```bash
# GitLab configuration
export PIPELEEK_GITLAB_URL="https://gitlab.example.com"
export PIPELEEK_GITLAB_TOKEN="glpat-xxxxxxxxxxxxxxxxxxxx"

# GitHub configuration
export PIPELEEK_GITHUB_TOKEN="ghp_xxxxxxxxxxxxxxxxxxxx"

# Common settings
export PIPELEEK_COMMON_THREADS="8"
export PIPELEEK_COMMON_TRUFFLEHOG_VERIFICATION="false"

# Run without flags
pipeleek gl scan
```

Environment variables follow the same priority: CLI flags > environment variables > config file > defaults.

### Supported Formats

Pipeleek supports multiple configuration file formats:

**YAML** (recommended):
```yaml
gitlab:
  token: glpat-xxxxxxxxxxxxxxxxxxxx
```

**JSON**:
```json
{
  "gitlab": {
    "token": "glpat-xxxxxxxxxxxxxxxxxxxx"
  }
}
```

**TOML**:
```toml
[gitlab]
token = "glpat-xxxxxxxxxxxxxxxxxxxx"
```

### Getting Started

1. Copy the example configuration:
   ```bash
   mkdir -p ~/.config/pipeleek
   curl -o ~/.config/pipeleek/config.yaml \
     https://raw.githubusercontent.com/CompassSecurity/pipeleek/main/.config/pipeleek.example.yaml
   ```

2. Edit the file with your credentials:
   ```bash
   vim ~/.config/pipeleek/config.yaml
   ```

3. Secure the file:
   ```bash
   chmod 600 ~/.config/pipeleek/config.yaml
   ```

4. Test the configuration:
   ```bash
   pipeleek gl scan --help
   ```

### Troubleshooting

**Config file not found:**
```bash
# Verify config file exists
ls -la ~/.config/pipeleek/config.yaml

# Use explicit path
pipeleek --config ~/.config/pipeleek/config.yaml gl scan
```

**Config values not being used:**
- Ensure YAML syntax is correct (use a YAML validator)
- Check that you're not setting conflicting CLI flags
- Use `--verbose` to see debug messages about config loading

**Permission denied:**
```bash
# Fix file permissions
chmod 600 ~/.config/pipeleek/config.yaml
```

## Related Documentation

- [Getting Started](getting_started.md) - Installation and basic usage
- [Logging](logging.md) - Configure logging options
- [Proxying](proxying.md) - Use Pipeleek through a proxy
