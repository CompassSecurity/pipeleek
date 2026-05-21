---
title: Credentials Scanning in GitLab Pipelines
description: Learn how to scan GitLab CI/CD pipelines for exposed secrets and credentials using Pipeleek.
keywords:
  - GitLab pipeline scanning
  - credential scanning
  - secrets detection
  - pipeline security
  - CI/CD security
---

# Credentials Scanning in GitLab Pipelines

> This example focuses on GitLab, but Pipeleek also supports other platforms. Refer to the documentation for details on additional integrations.

Suppose you're conducting a penetration test and have access to a GitLab instance with a user account. Your goal is to scan the pipelines for exposed secrets and credentials.

Start by creating a personal access token (`Menu` → `Preferences` → `Access Tokens`) and grant it read access scopes. Additionally, use your browser's developer tools to extract the session cookie (`_gitlab_session`).

For an initial scan, target all repositories you can access, including public ones. To keep the scan fast and broad, limit it to the latest 15 jobs per project:

```bash
pipeleek gl scan -u https://gitlab.com -t glpat-[redacted] --cookie [redacted] --artifacts --job-limit 15
2025-09-30T09:53:30Z info Gitlab Version Check revision=f0455ea9f90 version=18.5.0-pre
2025-09-30T09:53:30Z info Fetching projects
2025-09-30T09:53:30Z info Provided GitLab session cookie is valid
2025-09-30T09:53:33Z hit SECRET confidence=low type=log jobName=archives-job ruleName=api_key url=gitlab.com/testgroup/project/-/jobs/11484162851 value="m$ mkdir archive_data $ echo \"datadog_api_key=secrets.txt file hit\" > archive_data/secrets_in_ar"
2025-09-30T09:53:36Z hit SECRET confidence=high type=log ruleName="Generic - 1719" url=gitlab.com/testgroup/project/-/jobs/11484162842 value="datadog_api_key=dotenv ONLY file hit, no other artifacts "
2025-09-30T09:53:37Z hit SECRET confidence=high type=artifact file=an_artifact.txt jobName=artifact-job ruleName="Generic - 1719" url=gitlab.com/testgroup/project/-/jobs/11484162833 value="datadog_api_key=secret_artifact_value "
```

As shown, Pipeleek can detect secrets in job logs and build artifacts. Security findings are logged at the custom `hit` level to distinguish them from regular warnings. Manually review the hits to verify if they're valid credentials. If you see `confidence=high-verified`, it's very likely a real credential, as Pipeleek has tested it against the respective service.

If you find a repository that looks particularly interesting e.g. `secret-pipelines`, you can scan all its job logs, not just the most recent ones:

```bash
pipeleek gl scan -u https://gitlab.com -t glpat-[redacted] --cookie [redacted] --artifacts --repo mygroup/my-secret-pipelines-project
```
