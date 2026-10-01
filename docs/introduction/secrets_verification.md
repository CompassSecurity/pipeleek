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

Pipeleek uses [TruffleHog](https://github.com/trufflesecurity/trufflehog) and [Betterleaks](https://github.com/betterleaks/betterleaks) to detect secrets in CI/CD logs and artifacts. When verification is enabled, both engines can check supported credentials against their providers.

### How It Works

When Pipeleek scans logs or artifacts, it uses three detection sources:

1. **Pattern-based detection**: Custom YAML rules from `rules.yml` collected by [Secrets Patterns Database](https://github.com/mazen160/secrets-patterns-db)
2. **Betterleaks rules**: Embedded default rules with keyword, path, capture, and false-positive filtering
3. **TruffleHog detectors**: Specialized detectors with active verification

The `--secrets-verification` option controls provider verification for both TruffleHog and Betterleaks. With verification enabled, either engine may make outbound requests to credential providers for supported credentials. Disable verification to scan without those provider checks; findings are still reported, but their confidence depends on the detection source:

- TruffleHog reports verified hits as `high-verified`. With verification disabled, supported detections are reported as `trufflehog-unverified`.
- Betterleaks reports a validation result of `valid` as `high-verified`. Without verification, all Betterleaks detections are reported at their rule confidence (`high`, `medium`, or `low`); Betterleaks has no separate unverified confidence level.

### Confidence Levels

Pipeleek assigns confidence levels to all detected secrets:

| Level                     | Source     | Description                                       | Verified |
| ------------------------- | ---------- | ------------------------------------------------- | -------- |
| **high-verified**         | TruffleHog, Betterleaks | Actively verified and confirmed working | ✅ Yes |
| **trufflehog-unverified** | TruffleHog | Detected but not verified (verification disabled) | ❌ No |
| **high**                  | rules.yml, Betterleaks | High confidence pattern match | ❌ No |
| **medium**                | rules.yml, Betterleaks | Medium confidence pattern match | ❌ No |
| **low**                   | rules.yml, Betterleaks | Low confidence pattern match | ❌ No |
| **custom**                | rules.yml | User-defined confidence level | ❌ No |

### Disabling Verification

For operational security (OpSec) or privacy, disable verification to prevent TruffleHog and Betterleaks from sending credential checks to provider APIs.

Use the `--secrets-verification=false` flag:

```bash
pipeleek gl scan -u https://gitlab.com -t glpat-xxxxx --secrets-verification=false
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
pipeleek gl scan -u https://gitlab.com -t glpat-[redacted] --secrets-verification=false --verbose
2025-09-30T11:39:08Z hit SECRET confidence=custom-confidence type=log jobName=build-job-hidden ruleName="Pipeleek Custom Rule" url=gitlab.com/testgroup/project/-/jobs/11547853360 value="PIPELEEK_HIT=secret"
```
