<p align="center">
  <img height="200" src="https://raw.githubusercontent.com/CompassSecurity/pipeleek/refs/heads/main/docs/pipeleek-anim.svg">
</p>

![GitHub Release](https://img.shields.io/github/v/release/CompassSecurity/pipeleek)
![GitHub commits since latest release](https://img.shields.io/github/commits-since/CompassSecurity/pipeleek/latest)

# Pipeleek

Pipeleek is a tool designed to scan CI/CD logs and artifacts for secrets.

It supports the following platforms:

- GitLab
- GitHub
- BitBucket
- Azure DevOps
- Gitea

Once secrets are discovered, further exploitation often requires additional tooling. Pipeleek provides several helper commands to assist with this process.

## Getting Started

To begin using Pipeleek, download the latest binary from the [Releases](https://github.com/CompassSecurity/pipeleek/releases) page.

### Quick Install (Linux/macOS)

Install the latest version with a single command:

```bash
curl -sL https://compasssecurity.github.io/pipeleek/install.sh | sh
```

> **⚠️ Security Warning:** Piping scripts directly to `sh` can be dangerous. Always review the script contents first at [https://compasssecurity.github.io/pipeleek/install.sh](https://compasssecurity.github.io/pipeleek/install.sh) before executing.

### Install with Go

Alternatively, install using Go:

```bash
go install github.com/CompassSecurity/pipeleek/cmd/pipeleek@latest
```

Detailed command documentation can be found in the [documentation](https://compasssecurity.github.io/pipeleek/introduction/getting_started/).

<hr>

<sub>Formerly known as Pipeleak. Name and design idea credits to @sploutchy.</sub>
