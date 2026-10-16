#!/usr/bin/env bash
# Publishes CI job reports as force-pushed orphan commits on branches
# ci-results/<prefix><name>, so a client that can only `git fetch` (no GitHub
# API) can read CI results:
#
#   git fetch -f origin 'refs/heads/ci-results/*:refs/remotes/origin/ci-results/*'
#   git show origin/ci-results/summary:status.txt
#   git show origin/ci-results/go:job.log
#
# Each branch holds status.txt (status, run, commit, UTC time) and job.log
# (last 400 lines, secrets scrubbed by .github/actions/ci-log). The commit is
# built with plumbing in a temporary bare repository: no checkout, no
# credentials left on disk, no third-party actions.
#
# Usage: ci-report-push.sh <dir containing downloaded ci-log-<name>/ artifacts>
# Env:
#   GH_TOKEN    token allowed to push (the job's GITHUB_TOKEN, contents: write)
#   PREFIX      branch-name prefix: "" for CI, "release-" for release runs
#   PUBLISH     space-separated name=job-id pairs to publish
#   SUMMARY     optional name=job-id pairs; also writes ci-results/<prefix>summary
#   NEEDS_JSON  toJSON(needs): result of jobs that uploaded no log (skipped...)
set -euo pipefail

logs_dir="${1:?usage: ci-report-push.sh <dir>}"
prefix="${PREFIX:-}"
: "${GH_TOKEN:?GH_TOKEN is required}"
needs_json="${NEEDS_JSON:-}"
[ -n "$needs_json" ] || needs_json='{}'

valid_name() { [[ "$1" =~ ^[A-Za-z0-9._-]+$ ]]; }
if [ -n "$prefix" ] && ! valid_name "$prefix"; then
  echo "::error::invalid PREFIX"; exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export GIT_DIR="$work/repo.git"
git init -q --bare "$GIT_DIR"
export GIT_AUTHOR_NAME="github-actions[bot]"
export GIT_AUTHOR_EMAIL="41898099+github-actions[bot]@users.noreply.github.com"
export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME" GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"

now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
run_url="$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID"
needs_summary="$(jq -r 'to_entries | map("\(.key)=\(.value.result)") | join(" ")' <<<"$needs_json")"

# Echo the report directory for <name>, synthesising one from `needs` when
# the job uploaded no log (skipped, cancelled, or died before collecting).
report_dir() {
  local name="$1" job="$2" dir result
  dir="$logs_dir/ci-log-$name"
  if [ -f "$dir/status.txt" ]; then
    [ -f "$dir/job.log" ] || echo "(no log captured)" > "$dir/job.log"
    echo "$dir"; return
  fi
  result="$(jq -r --arg j "$job" '.[$j].result // "unknown"' <<<"$needs_json")"
  dir="$work/synth/$name"
  mkdir -p "$dir"
  {
    echo "job: $name"
    echo "status: $result"
    echo "note: the job uploaded no log (it was skipped, cancelled or failed before collecting)"
    echo "workflow: $GITHUB_WORKFLOW"
    echo "run_id: $GITHUB_RUN_ID (attempt $GITHUB_RUN_ATTEMPT)"
    echo "run_url: $run_url"
    echo "commit: $GITHUB_SHA"
    echo "ref: $GITHUB_REF"
    echo "event: $GITHUB_EVENT_NAME"
    echo "time_utc: $now"
  } > "$dir/status.txt"
  printf 'No log for this job (result: %s).\nResults of the jobs this report waited for: %s\n' \
    "$result" "$needs_summary" > "$dir/job.log"
  echo "$dir"
}

status_of() { sed -n 's/^status: //p' "$1/status.txt" | head -n 1; }

refspecs=()
commit_report() {
  local branch="$1" dir="$2" st blob_log blob_status tree commit
  st="$(status_of "$dir")"
  blob_log="$(git hash-object -w "$dir/job.log")"
  blob_status="$(git hash-object -w "$dir/status.txt")"
  tree="$(printf '100644 blob %s\tjob.log\n100644 blob %s\tstatus.txt\n' "$blob_log" "$blob_status" | git mktree)"
  commit="$(git commit-tree "$tree" -m "ci-results/$branch: ${st:-unknown} @ ${GITHUB_SHA:0:12} (run $GITHUB_RUN_ID)")"
  refspecs+=("+$commit:refs/heads/ci-results/$branch")
  printf '  %-34s %s\n' "ci-results/$branch" "${st:-unknown}"
}

echo "Reports for $GITHUB_SHA:"
for pair in ${PUBLISH:-}; do
  name="${pair%%=*}"; job="${pair#*=}"
  if ! valid_name "$name" || ! valid_name "$job"; then echo "::error::bad PUBLISH entry: $pair"; exit 1; fi
  commit_report "$prefix$name" "$(report_dir "$name" "$job")"
done

if [ -n "${SUMMARY:-}" ]; then
  sdir="$work/summary"; mkdir -p "$sdir"
  overall=success; lines=""
  for pair in $SUMMARY; do
    name="${pair%%=*}"; job="${pair#*=}"
    if ! valid_name "$name" || ! valid_name "$job"; then echo "::error::bad SUMMARY entry: $pair"; exit 1; fi
    st="$(status_of "$(report_dir "$name" "$job")")"
    [ "$st" = success ] || overall=failure
    lines+="$(printf '%-24s %s' "$prefix$name" "${st:-unknown}")"$'\n'
  done
  {
    echo "job: ${prefix}summary"
    echo "status: $overall"
    echo "workflow: $GITHUB_WORKFLOW"
    echo "run_id: $GITHUB_RUN_ID (attempt $GITHUB_RUN_ATTEMPT)"
    echo "run_url: $run_url"
    echo "commit: $GITHUB_SHA"
    echo "ref: $GITHUB_REF"
    echo "event: $GITHUB_EVENT_NAME"
    echo "time_utc: $now"
    echo "jobs:"
    printf '%s' "$lines"
  } > "$sdir/status.txt"
  printf 'Per-job reports: git show origin/ci-results/<name>:job.log\n\n%s' "$lines" > "$sdir/job.log"
  commit_report "${prefix}summary" "$sdir"
fi

[ "${#refspecs[@]}" -gt 0 ] || { echo "nothing to publish"; exit 0; }

# Authenticate with an extra header (never in the URL or on disk).
auth="$(printf 'x-access-token:%s' "$GH_TOKEN" | base64 | tr -d '\n')"
echo "::add-mask::$auth"
remote="$GITHUB_SERVER_URL/$GITHUB_REPOSITORY.git"
for attempt in 1 2 3; do
  if git -c "http.extraheader=AUTHORIZATION: basic $auth" push --force --quiet "$remote" "${refspecs[@]}"; then
    echo "pushed ${#refspecs[@]} ci-results branch(es)"
    exit 0
  fi
  echo "push failed (attempt $attempt), retrying"
  sleep $((attempt * 5))
done
echo "::error::could not push ci-results branches"
exit 1
