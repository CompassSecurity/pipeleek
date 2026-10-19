---
title: Secret Detection, Verification, and Rules
description: Understand Pipeleek's detection engines, confidence levels, custom rules, and optional rule downloads.
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

# Secret Detection, Verification, and Rules

Pipeleek scans CI/CD logs and artifacts using:

- **YAML rules:** 15 embedded Pipeleek rules plus optional working-directory `rules.yml`.
- **[Betterleaks](https://github.com/betterleaks/betterleaks):** embedded rules with false-positive filtering.
- **[TruffleHog](https://github.com/trufflesecurity/trufflehog):** specialized credential detectors.

## Verification

Verification is enabled by default. `--secrets-verification` controls provider checks for TruffleHog, Betterleaks, and the GitLab detector. These checks can send detected credentials to provider APIs.

| Source | Verification enabled | Verification disabled |
| ------ | -------------------- | --------------------- |
| TruffleHog | Only successfully verified findings (`verified`) | Returned candidates (`trufflehog`) |
| Betterleaks | Valid credentials use `verified`; invalid/revoked results are suppressed; other retained findings use rule confidence | Rule confidence (`high`, `medium`, or `low`) |
| YAML rules | Rule confidence; no provider checks | Unchanged |

A verification error does not prove a credential is invalid. TruffleHog findings with verification errors are suppressed when verification is enabled. Disabling verification can expose more false positives.

Unverified TruffleHog results never receive `high`. The separate Pipeleek GitLab detector and YAML rules can report the same token at `high` based on its pattern.

To skip provider checks:

```bash
pipeleek gl scan -u https://gitlab.com -t glpat-[redacted] --secrets-verification=false
```

## Confidence and Filtering

| Level | Meaning |
| ----- | ------- |
| `verified` | Successfully verified credential |
| `trufflehog` | Non-verified TruffleHog candidate; not a confidence ranking |
| `high`, `medium`, `low` | Pattern confidence, not proof that a credential works |
| User-defined label | Confidence assigned by a custom YAML rule |

`--confidence` filters results from every engine. An empty filter includes all levels reported under the verification policy above. Filtering does not disable provider checks.

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

To install the [Secrets Patterns Database](https://github.com/mazen160/secrets-patterns-db) stable ruleset:

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

Built-in rules include GitLab token patterns and predefined variables such as `GITLAB_USER_ID` and `KUBECONFIG`. Identifier/path matches are indicators to review, not proof of a leaked credential.

Create `rules.yml` in your working directory to add rules. An exact-name match overrides a built-in in the YAML engine; other names add rules. Overrides do not affect the separate GitLab detector or other engines. Without this file, scans use the embedded defaults.

For example, to report `PIPELEEK_` markers with a custom confidence:

```yaml
patterns:
  - pattern:
      name: Pipeleek Custom Rule
      regex: PIPELEEK_[A-Z0-9_]+
      confidence: custom-confidence
```

Each rule needs a nonempty name, valid Go regex, and nonempty confidence label. Duplicate names, invalid YAML/regexes, and unreadable files fail initialization.
