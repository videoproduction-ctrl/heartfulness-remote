#!/usr/bin/env bash
# Collects this job's CI report into $RUNNER_TEMP/ci-report/$REPORT_NAME:
#   status.txt  job status, run, commit, UTC time
#   job.log     last 400 lines of $RUNNER_TEMP/job.log, secrets scrubbed
# Runs on Linux, macOS and Windows (Git Bash).
set -euo pipefail

name="${REPORT_NAME:?}"
case "$name" in
  *[!A-Za-z0-9._-]*) echo "::error::invalid report name: $name"; exit 1 ;;
esac
out="$RUNNER_TEMP/ci-report/$name"
mkdir -p "$out"

{
  echo "job: $name"
  echo "status: ${JOB_STATUS:-unknown}"
  echo "workflow: $GITHUB_WORKFLOW"
  echo "run_id: $GITHUB_RUN_ID (attempt $GITHUB_RUN_ATTEMPT)"
  echo "run_url: $GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID"
  echo "commit: $GITHUB_SHA"
  echo "ref: $GITHUB_REF"
  echo "event: $GITHUB_EVENT_NAME"
  echo "runner: $RUNNER_OS/$RUNNER_ARCH"
  echo "time_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$out/status.txt"

log="$RUNNER_TEMP/job.log"
if [ -s "$log" ]; then
  # Scrub the whole log first (so a key block cut by `tail` cannot leak),
  # then keep the last 400 lines. CI jobs hold no secrets; this is defence
  # in depth because the report bypasses the Actions log masking.
  perl -0777 -pe '
    s/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(-----END [A-Z0-9 ]*PRIVATE KEY-----|\z)/[REDACTED PRIVATE KEY]/gs;
    s/\b(gh[pousr]_)[A-Za-z0-9]{20,}/$1\[REDACTED]/g;
    s/\bgithub_pat_[A-Za-z0-9_]{20,}/github_pat_[REDACTED]/g;
    s/(x-access-token:)[^\s@]+/$1\[REDACTED]/gi;
    s/(authorization:\s*(?:basic|bearer|token)\s+)\S+/$1\[REDACTED]/gi;
    s/(\bbearer\s+)[A-Za-z0-9._~+\/-]{16,}=*/$1\[REDACTED]/gi;
  ' "$log" | tail -n 400 > "$out/job.log"
else
  echo "(no log captured)" > "$out/job.log"
fi
cat "$out/status.txt"
