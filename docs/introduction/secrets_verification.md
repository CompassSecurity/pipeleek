---
title: Secret Verification with TruffleHog
description: Learn how Pipeleek uses TruffleHog to automatically verify detected secrets, understand confidence levels, and how to disable verification for operational security.
keywords:
  - secret verification
  - TruffleHog
  - credential validation
  - confidence levels
  - verified
  - secret detection
  - credential testing
  - opsec
---

Pipeleek uses [TruffleHog](https://github.com/trufflesecurity/trufflehog) and [Betterleaks](https://github.com/betterleaks/betterleaks) to detect secrets in CI/CD logs and artifacts. When verification is enabled, both engines can check supported credentials against their providers.

### How It Works

When Pipeleek scans logs or artifacts, it uses three detection sources:

1. **Pattern-based detection**: 15 embedded Pipeleek YAML rules plus optional custom rules from local `rules.yml`. Scans never download rules automatically.
2. **Betterleaks rules**: Embedded default rules with keyword, path, capture, and false-positive filtering
3. **TruffleHog detectors**: Specialized detectors with active verification

The `--secrets-verification` option controls provider verification for both TruffleHog and Betterleaks. With verification enabled, either engine may make outbound requests to credential providers for supported credentials. Disable verification to scan without those provider checks; findings are still reported, but their confidence depends on the detection source:

- With verification enabled, TruffleHog reports only successfully verified hits as `verified`. Other candidates, including those with verification errors, are suppressed. With verification disabled, returned non-verified candidates are reported as `trufflehog`.
- Betterleaks reports a validation result of `valid` as `verified`. Without verification, all Betterleaks detections are reported at their rule confidence (`high`, `medium`, or `low`); Betterleaks has no separate unverified confidence level.
- The GitLab URL-aware detector uses `verified` for successful verification against your configured instance and `high` for retained non-verified detections. Existing GitLab rejection behavior and Betterleaks invalid/revoked suppression are unchanged.

Disabling verification exposes more TruffleHog candidates and may mean more false positives; `trufflehog` indicates a detection source, not a confidence ranking or a working credential. A failed verification request does not prove that a credential is invalid, but the candidate is suppressed when verification is enabled.

### Confidence Levels

Pipeleek assigns confidence levels to all detected secrets:

| Level | Source | Description | Verified |
| ----- | ------ | ----------- | -------- |
| **verified** | TruffleHog, Betterleaks, GitLab detector | Successfully verified against a provider | Yes |
| **trufflehog** | TruffleHog | Non-verified detection reported when verification is disabled | No |
| **high** | Embedded/custom YAML, Betterleaks, GitLab detector | High confidence pattern match | No |
| **medium** | Embedded/custom YAML, Betterleaks | Medium confidence pattern match | No |
| **low** | Custom YAML, Betterleaks | Low confidence pattern match | No |
| **custom** | Custom YAML | User-defined confidence label | No |

### Disabling Verification

For operational security (OpSec) or privacy, disable verification to prevent TruffleHog and Betterleaks from sending credential checks to provider APIs.

Use the `--secrets-verification=false` flag:

```bash
pipeleek gl scan -u https://gitlab.com -t glpat-[redacted] --secrets-verification=false
```

### Confidence Filtering

Results from every engine can be filtered using the `--confidence` flag. An empty filter reports all levels. Filtering does not disable provider verification.

```bash
# Higher-confidence findings, including verified credentials
pipeleek gl scan -u https://gitlab.com -t glpat-[redacted] --confidence=verified,high

# Only successfully verified credentials
pipeleek gl scan -u https://gitlab.com -t glpat-[redacted] --confidence=verified

# Only non-verified TruffleHog candidates
pipeleek gl scan -u https://gitlab.com -t glpat-[redacted] --secrets-verification=false --confidence=trufflehog
```

## Custom Rules

### Optional external rules download

To explicitly install the Secrets Patterns Database stable ruleset from
`mazen160/secrets-patterns-db`, run:

```bash
pipeleek rules download
```

This writes `rules.yml` in the current directory, which subsequent scans load alongside
the embedded rules. External regex rules can substantially increase false positives
and do not verify credentials. Scans never download or update rules automatically.
The download uses Pipeleek's HTTP client and its global proxy, TLS, and timeout settings.

Existing files are protected unless you explicitly replace them:

```bash
pipeleek rules download --force
pipeleek rules download --output additional-rules.yml
```

`--output` only changes where the download is saved; scans still load working-directory
`rules.yml`. Downloads are validated for nonempty rule sets, required fields, duplicate
names, and valid Go regexes before saving. Failed downloads or validation leave existing
files unchanged.

### Local customization

The built-in definitions live in `pkg/scanner/rules/rules.yaml` and are embedded in the binary. They include GitLab token patterns and the predefined-variable rule, which intentionally also matches identifiers and paths such as `GITLAB_USER_ID` and `KUBECONFIG`. These matches are indicators to review, not proof of a leaked credential.

To add a rule, create `rules.yml` in your working directory. Pipeleek neither downloads nor creates this file. A rule with the same exact name as a built-in overrides that built-in in the YAML detection engine; other names add rules. Overrides do not alter the separate GitLab verifier or other engines.

For example:

```yaml
patterns:
  - pattern:
      name: AWS API Key
      regex: AKIA[0-9A-Z]{16}
      confidence: high
```

Each rule requires a nonempty name, valid Go regex, and nonempty confidence label. Duplicate names within one file, invalid YAML/regexes, and unreadable files fail initialization with an error. A missing file is normal and uses embedded defaults. Regexes are compiled during initialization rather than for each scanned item.

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

## Migration

- Update scripts and confidence filters: `high-verified` is now `verified`; `trufflehog-unverified` is now `trufflehog`. Legacy filter names are not aliases. Custom YAML confidence labels remain user-defined.
- Existing local `rules.yml` files are preserved and loaded as custom rules. A previously downloaded Secrets Patterns Database will therefore still contribute its patterns. Back up and remove or curate that file if you want only the 15 embedded defaults.
- Automatic rule downloads and the old Go helpers (`rules.DownloadRules` and `scanner.DownloadRules`) have been removed. Use `pipeleek rules download` for an explicit external rules download. Go callers should initialize the embedded/local rules with `InitRules`.
- The live UI includes a `trufflehog` filter and count. These candidates are outside the verified/high severity ranking; the existing “any” notification threshold includes them.
