#!/usr/bin/env bash
set -euo pipefail

# Pre-release guard:
# 1) Diff current ref against latest release tag (or user-specified base)
# 2) Enforce changed-file allowlist
# 3) Build release and current binaries in isolated worktrees and diff --help output
# 4) Run parse/smoke checks for critical commands
# 5) Run non-e2e tests and optional linters/security checks

BASE_REF="${1:-}"
HEAD_REF="${2:-HEAD}"

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

if [[ -z "$BASE_REF" ]]; then
  BASE_REF="$(git tag --sort=-v:refname | head -n1)"
fi

if [[ -z "$BASE_REF" ]]; then
  echo "ERROR: Could not determine latest release tag. Pass BASE_REF explicitly:"
  echo "  scripts/pre_release_guard.sh <base_ref> [head_ref]"
  exit 1
fi

if ! git rev-parse --verify "$BASE_REF^{commit}" >/dev/null 2>&1; then
  echo "ERROR: BASE_REF '$BASE_REF' does not resolve to a commit"
  exit 1
fi

if ! git rev-parse --verify "$HEAD_REF^{commit}" >/dev/null 2>&1; then
  echo "ERROR: HEAD_REF '$HEAD_REF' does not resolve to a commit"
  exit 1
fi

ALLOWLIST_REGEX="${ALLOWLIST_REGEX:-^(internal/cmd/.*/scan/|internal/cmd/configcmd/|pkg/config/|pipeleek.example.yaml$|Makefile$|.*_test.go$)}"
STRICT_ALLOWLIST="${STRICT_ALLOWLIST:-0}"
FAST_MODE="${FAST_MODE:-0}"

echo "== Pre-release guard =="
echo "Base ref : $BASE_REF"
echo "Head ref : $HEAD_REF"
echo "Allowlist strict mode: $STRICT_ALLOWLIST"
echo "Fast mode: $FAST_MODE"
echo

echo "[1/6] Checking changed files against allowlist"
CHANGED_FILES="$(git diff --name-only "$BASE_REF..$HEAD_REF")"
if [[ -z "$CHANGED_FILES" ]]; then
  echo "No changed files between refs."
else
  echo "$CHANGED_FILES"
fi

echo
UNEXPECTED_FILES="$(printf '%s\n' "$CHANGED_FILES" | grep -Ev "$ALLOWLIST_REGEX" || true)"
if [[ -n "$UNEXPECTED_FILES" ]]; then
  echo "Unexpected changed files detected (outside allowlist):"
  printf '%s\n' "$UNEXPECTED_FILES"
  if [[ "$STRICT_ALLOWLIST" == "1" ]]; then
    echo "STRICT_ALLOWLIST=1, stopping on allowlist mismatch."
    exit 1
  fi
  echo "Continuing in report mode (STRICT_ALLOWLIST=$STRICT_ALLOWLIST)."
else
  echo "Allowlist check passed."
fi

echo
echo "[2/6] Building release and current binaries in isolated worktrees"
TMP_DIR="$(mktemp -d)"
REL_WT="$TMP_DIR/release"
HEAD_WT="$TMP_DIR/head"

cleanup() {
  set +e
  git worktree remove --force "$REL_WT" >/dev/null 2>&1
  git worktree remove --force "$HEAD_WT" >/dev/null 2>&1
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

git worktree add --detach "$REL_WT" "$BASE_REF" >/dev/null
git worktree add --detach "$HEAD_WT" "$HEAD_REF" >/dev/null

(
  cd "$REL_WT"
  CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o pipeleek-check ./cmd/pipeleek
)
(
  cd "$HEAD_WT"
  CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o pipeleek-check ./cmd/pipeleek
)

echo "Build check passed."

echo
echo "[3/6] Diffing command help surface"
REL_HELP="$TMP_DIR/release-help.txt"
HEAD_HELP="$TMP_DIR/head-help.txt"
HELP_DIFF="$TMP_DIR/help.diff"

collect_help() {
  local bin="$1"
  {
    "$bin" --help
    "$bin" gl --help
    "$bin" gh --help
    "$bin" bb --help
    "$bin" ad --help
    "$bin" gitea --help
    "$bin" jenkins --help
    "$bin" circle --help
    "$bin" config --help || true
  }
}

collect_help "$REL_WT/pipeleek-check" >"$REL_HELP"
collect_help "$HEAD_WT/pipeleek-check" >"$HEAD_HELP"

if diff -u "$REL_HELP" "$HEAD_HELP" >"$HELP_DIFF"; then
  echo "Help output unchanged between refs."
else
  echo "Help output differs (expected for intentional CLI changes). Diff:"
  cat "$HELP_DIFF"
fi

echo
echo "[4/6] Running command parse/smoke checks on current ref"
(
  cd "$HEAD_WT"
  ./pipeleek-check gl scan --help >/dev/null
  ./pipeleek-check gh scan --help >/dev/null
  ./pipeleek-check bb scan --help >/dev/null
  ./pipeleek-check ad scan --help >/dev/null
  ./pipeleek-check gitea scan --help >/dev/null
  ./pipeleek-check jenkins scan --help >/dev/null
  ./pipeleek-check circle scan --help >/dev/null
  ./pipeleek-check config gen --help >/dev/null
)
echo "Smoke checks passed."

echo
echo "[5/6] Running non-e2e tests on current workspace"
go test $(go list ./... | grep -v /tests/e2e) --timeout=10m

echo
echo "[6/6] Running optional static checks (if installed)"
if [[ "$FAST_MODE" == "1" ]]; then
  echo "Skipping gosec and golangci-lint in fast mode"
else
  if command -v gosec >/dev/null 2>&1; then
    gosec ./cmd/... ./internal/... ./pkg/...
  else
    echo "Skipping gosec: not installed"
  fi

  if command -v golangci-lint >/dev/null 2>&1; then
    golangci-lint run --timeout=10m
  else
    echo "Skipping golangci-lint: not installed"
  fi
fi

echo
echo "Pre-release guard completed successfully for $HEAD_REF against $BASE_REF"
