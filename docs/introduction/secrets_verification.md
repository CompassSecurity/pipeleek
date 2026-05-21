---
title: Secret Verification with TruffleHog
description: Learn how Pipeleek uses TruffleHog to automatically verify detected secrets, understand confidence levels, and how to disable verification for operational security.
keywords:
  - secret verification
  - TruffleHog
  - credential validation
  - confidence levels
  - high-verified
  - secret detection
  - credential testing
  - opsec
---

Pipeleek integrates [TruffleHog v3](https://github.com/trufflesecurity/trufflehog) to automatically detect and verify secrets in CI/CD logs and artifacts. TruffleHog provides many detectors for various services and platforms, each with built-in verification capabilities.

### How It Works

When Pipeleek scans logs or artifacts, it uses two detection engines in parallel:

1. **Pattern-based detection**: Custom YAML rules from `rules.yml` collected by [Secrets Patterns Database](https://github.com/mazen160/secrets-patterns-db)
2. **TruffleHog detectors**: Specialized detectors with active verification

The TruffleHog engine:

1. **Scans** text for secrets using pattern matching
2. **Extracts** potential credentials (API keys, tokens, passwords)
3. **Verifies** credentials by attempting authentication with the target service
4. **Reports** only verified secrets (by default)

### Confidence Levels

Pipeleek assigns confidence levels to all detected secrets:

| Level                     | Source     | Description                                       | Verified |
| ------------------------- | ---------- | ------------------------------------------------- | -------- |
| **high-verified**         | TruffleHog | Actively verified and confirmed working           | ✅ Yes   |
| **trufflehog-unverified** | TruffleHog | Detected but not verified (verification disabled) | ❌ No    |
| **high**                  | rules.yml  | High confidence pattern match                     | ❌ No    |
| **medium**                | rules.yml  | Medium confidence pattern match                   | ❌ No    |
| **low**                   | rules.yml  | Low confidence pattern match                      | ❌ No    |
| **custom**                | rules.yml  | User-defined confidence level                     | ❌ No    |

### Disabling Verification

For operational security (OpSec) or simply due to privacy concerns, you should disable verification.

Use the `--truffle-hog-verification=false` flag:

```bash
pipeleek gl scan -u https://gitlab.com -t glpat-xxxxx --truffle-hog-verification=false
```

### Confidence Filtering

Results can be filtered by confidence, using the `--confidence` flag.

```bash
pipeleek gl scan -u https://gitlab.com -t glpat-xxxxx --confidence=high-verified,high
```

## Custom Rules

To scan for a specific pattern, edit the `rules.yml` file Pipeleek creates on the first run. You can remove/add/alter rules as you like.

By default the rules look something like this:

```yaml
patterns:
  - pattern:
      name: AWS API Gateway
      regex: "[0-9a-z]+.execute-api.[0-9a-z._-]+.amazonaws.com"
      confidence: low
  - pattern:
      name: AWS API Key
      regex: AKIA[0-9A-Z]{16}
      confidence: high
```

You can create additional custom rules.

> **💡Tip:** Test your regexes at [regex101.com](https://regex101.com/) (select Golang flavor).

A simple example that detects strings that follow the Regex pattern `PIPELEEK_.*` and that are logged with a custom confidence:

```yaml
patterns:
  - pattern:
      name: Pipeleek Custom Rule
      regex: PIPELEEK_.*
      confidence: custom-confidence
```

When you run Pipeleek, you'll see results for your custom rule and any built-in rules:

```bash
pipeleek gl scan -u https://gitlab.com -t glpat-[redacted] --truffle-hog-verification=false --verbose
2025-09-30T11:39:08Z hit SECRET confidence=custom-confidence type=log jobName=build-job-hidden ruleName="Pipeleek Custom Rule" url=gitlab.com/testgroup/project/-/jobs/11547853360 value="PIPELEEK_HIT=secret"
```
