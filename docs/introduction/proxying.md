---
title: Using Pipeleek with Proxies
description: Learn how to configure Pipeleek to work with HTTP and SOCKS5 proxies for intercepting traffic, testing, and accessing internal networks.
keywords:
  - proxy
  - HTTP proxy
  - SOCKS5 proxy
  - Burp Suite
  - traffic interception
  - proxy configuration
  - HTTP_PROXY
  - network proxy
  - ignore proxy
---

Pipeleek supports routing all HTTP/HTTPS traffic through a proxy server. This is useful for:

- **Traffic interception**: Analyze API calls with tools like Burp Suite or mitmproxy
- **Internal network access**: Connect to internal GitLab/Gitea/... instances through SOCKS5 proxies

## Proxy Configuration

Pipeleek uses the standard `HTTP_PROXY` environment variable for proxy configuration.

```bash
HTTP_PROXY=http://127.0.0.1:8080 pipeleek gl scan -u https://gitlab.com -t glpat-xxxxx
```

SOCKS5 can be used as well.

```bash
HTTP_PROXY=socks5://127.0.0.1:1080 pipeleek gl scan -u https://gitlab.internal.company.com -t glpat-xxxxx
```

### Using the `--proxy` Flag

Alternatively, use the `--proxy` flag to set any proxy from the command line without relying on `HTTP_PROXY`. It accepts both HTTP and SOCKS5 URLs and takes precedence over the environment variable:

```bash
# HTTP proxy
pipeleek --proxy http://127.0.0.1:8080 gl scan -u https://gitlab.com -t glpat-xxxxx

# SOCKS5 proxy
pipeleek --proxy socks5://127.0.0.1:1080 gl scan -u https://gitlab.internal.company.com -t glpat-xxxxx
```

## Ignoring Proxy Configuration

In some environments, `HTTP_PROXY` may be set system-wide but you don't want Pipeleek to use it. Use the `--ignore-proxy` flag to bypass proxy detection:

```bash
HTTP_PROXY=http://127.0.0.1:8080 pipeleek --ignore-proxy gl scan -u https://gitlab.com -t glpat-xxxxx
```

## TLS Certificate Verification

By default, Pipeleek skips TLS certificate verification so that self-hosted instances with self-signed certificates work out of the box. Use `--tls-verification` to enforce certificate validation:

```bash
pipeleek --tls-verification gl scan --token glpat-xxx --url https://gitlab.example.com
```

## HTTP Timeout

Use `--http-timeout` to set a per-request timeout. This is useful when scanning slow or unreliable targets:

```bash
pipeleek --http-timeout 30s gl scan --token glpat-xxx --url https://gitlab.example.com
```

Accepts any Go duration string: `30s`, `2m`, `90s`, etc. The default is no timeout.

> **Note:** `--http-timeout` applies to platforms that use `GetPipeleekHTTPClient` (GitLab, Gitea, GitHub, Jenkins, CircleCI, NIST, and rule downloads). Bitbucket and Azure DevOps inject only the transport via `GetPipeleekTransport` and are not affected by this flag.

## Platform Scope

All proxy and TLS flags share a single HTTP transport injected into every platform client:

| Flag | Default | Applies to |
|---|---|---|
| `--tls-verification` | `false` | All platforms |
| `--ignore-proxy` | `false` | All platforms |
| `--proxy <url>` | _(none)_ | All platforms |
| `--http-timeout <duration>` | _(no timeout)_ | GitLab, Gitea, Jenkins, CircleCI, NIST (not Bitbucket/DevOps) |

> **Note:** The GitHub SDK uses a dedicated rate-limit transport (`go-github-ratelimit`) that cannot be replaced. TLS and proxy settings still apply to GitHub via the shared transport layer.
