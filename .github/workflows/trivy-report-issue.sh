#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Authors of KubeArmor

# Opens a GitHub tracking issue when a Trivy scan reports vulnerabilities, or
# appends a comment to the already open tracking issue so that every push to
# main does not create a duplicate.
#
# Input (environment):
#   GH_TOKEN              token with "issues: write" on the repository (used by gh)
#   GH_REPO               "owner/repo" to operate on
#   TRIVY_ISSUE_TITLE     exact issue title, also used as the deduplication key
#   TRIVY_REPORT_DIR      directory with "<component>.txt" reports and
#                         "failed-components.tsv" (default: trivy-reports)
#   TRIVY_LABELS          comma separated labels (default: "security,trivy")
#   TRIVY_SEVERITY        severities the scan ran with (default: "CRITICAL,HIGH")
#   TRIVY_ARTIFACT_NAME   name of the artifact holding the full reports
#   GITHUB_SHA, GITHUB_SERVER_URL, GITHUB_RUN_ID, GITHUB_WORKFLOW
#                         standard GitHub Actions context, used for the links

set -euo pipefail

REPO="${GH_REPO:-${GITHUB_REPOSITORY:-}}"
TITLE="${TRIVY_ISSUE_TITLE:?TRIVY_ISSUE_TITLE must be set}"
REPORT_DIR="${TRIVY_REPORT_DIR:-trivy-reports}"
LABELS="${TRIVY_LABELS:-security,trivy}"
SEVERITY="${TRIVY_SEVERITY:-CRITICAL,HIGH}"
ARTIFACT_NAME="${TRIVY_ARTIFACT_NAME:-trivy-reports}"
SERVER_URL="${GITHUB_SERVER_URL:-https://github.com}"
SHA="${GITHUB_SHA:-unknown}"
RUN_ID="${GITHUB_RUN_ID:-}"
WORKFLOW="${GITHUB_WORKFLOW:-Trivy scan}"

# GitHub rejects issue bodies and comments larger than 65536 characters. Stay
# well below that so the reports can be truncated with a readable notice.
MAX_BODY=60000

MANIFEST="$REPORT_DIR/failed-components.tsv"

log() {
  echo "[trivy-report-issue] $*" >&2
}

if [ -z "$REPO" ]; then
  log "GH_REPO (or GITHUB_REPOSITORY) must be set"
  exit 1
fi

if [ ! -s "$MANIFEST" ] || ! grep -q '[^[:space:]]' "$MANIFEST"; then
  log "no failing components recorded in $MANIFEST, nothing to report"
  exit 0
fi

if [ -n "$RUN_ID" ]; then
  RUN_URL="$SERVER_URL/$REPO/actions/runs/$RUN_ID"
else
  RUN_URL=""
fi

# Creates a label when it is missing. Labels that cannot be ensured are dropped
# from the issue instead of failing the whole run, because "gh issue create"
# rejects labels that do not exist in the repository.
ensure_label() {
  local name="$1" color="$2" description="$3" output=""

  if output="$(gh label create "$name" --repo "$REPO" --color "$color" \
    --description "$description" 2>&1)"; then
    log "created label '$name'"
    return 0
  fi

  if printf '%s' "$output" | grep -qi "already exists"; then
    log "label '$name' already exists"
    return 0
  fi

  log "WARNING: could not ensure label '$name': $output"
  return 1
}

label_description() {
  case "$1" in
  security) echo "Security related issue" ;;
  trivy) echo "Reported by the Trivy image scan" ;;
  *) echo "Created by the Trivy scan workflow" ;;
  esac
}

label_color() {
  case "$1" in
  security) echo "d93f0b" ;;
  trivy) echo "1d76db" ;;
  *) echo "ededed" ;;
  esac
}

# Ensure every requested label exists and keep the ones that are usable.
usable_labels=""
old_ifs="$IFS"
IFS=','
for label in $LABELS; do
  IFS="$old_ifs"
  [ -n "$label" ] || continue
  if ensure_label "$label" "$(label_color "$label")" "$(label_description "$label")"; then
    usable_labels="${usable_labels:+$usable_labels,}$label"
  fi
  IFS=','
done
IFS="$old_ifs"

# Looks for an already open tracking issue with exactly this title. The label
# filter keeps the listing small; it is dropped when no label could be ensured.
find_open_issue() {
  local args=(issue list --repo "$REPO" --state open --limit 100)
  local label

  if [ -n "$usable_labels" ]; then
    old_ifs="$IFS"
    IFS=','
    for label in $usable_labels; do
      IFS="$old_ifs"
      args+=(--label "$label")
      IFS=','
    done
    IFS="$old_ifs"
  fi

  # shellcheck disable=SC2054 # "number,title" is a single gh argument
  args+=(--json number,title --template '{{range .}}{{.number}}{{"\t"}}{{.title}}{{"\n"}}{{end}}')

  gh "${args[@]}" | awk -F'\t' -v title="$TITLE" '$2 == title { print $1; exit }'
}

# Prints a report, shortened to at most "$2" bytes so that the body stays within
# the GitHub size limit.
#
# "head -c" caps the byte count, and "sed '\$ d'" then drops the trailing line it
# may have cut in half. Everything that survives is therefore a whole line, which
# keeps the Trivy table readable and, because the table is drawn with three byte
# box characters, keeps the output valid UTF-8. Counting bytes here rather than
# with awk's length() also avoids depending on whether the runner's awk is
# multibyte aware.
render_report() {
  local file="$1" budget="$2" size

  if [ ! -s "$file" ]; then
    echo "(no report was captured for this component, the scan step may have failed before writing one)"
    return 0
  fi

  size="$(wc -c <"$file" | tr -d ' ')"
  if [ "$size" -le "$budget" ]; then
    cat "$file"
    return 0
  fi

  head -c "$budget" "$file" | sed '$ d'
  printf '\n[... truncated at ~%s of %s bytes, download the "%s" artifact from the workflow run for the full report ...]\n' \
    "$budget" "$size" "$ARTIFACT_NAME"
}

# Writes the issue body ("create") or the follow up comment ("comment") to "$2".
render_body() {
  local mode="$1" out="$2"
  local name image count used budget

  : >"$out"

  if [ "$mode" = "create" ]; then
    {
      echo "Trivy reported \`$SEVERITY\` vulnerabilities in the images built from \`main\`."
      echo
      echo "This issue is maintained automatically by the \`$WORKFLOW\` workflow: every"
      echo "later failing scan is appended as a comment instead of opening a new issue."
      echo "Close it once the scans are green again."
      echo
    } >>"$out"
  else
    {
      echo "### Still failing on a newer commit"
      echo
    } >>"$out"
  fi

  {
    echo "| | |"
    echo "| --- | --- |"
    echo "| Commit | [\`${SHA:0:7}\`]($SERVER_URL/$REPO/commit/$SHA) |"
    if [ -n "$RUN_URL" ]; then
      echo "| Workflow run | [$WORKFLOW]($RUN_URL) |"
    fi
    echo "| Severities | \`$SEVERITY\` (unfixed vulnerabilities ignored) |"
    echo
    echo "**Affected images**"
    echo
  } >>"$out"

  while IFS=$'\t' read -r name image; do
    [ -n "$name" ] || continue
    echo "- \`${image:-$name}\`" >>"$out"
  done <"$MANIFEST"

  echo >>"$out"

  count="$(grep -c . "$MANIFEST" || true)"
  [ "${count:-0}" -gt 0 ] || count=1
  used="$(wc -c <"$out" | tr -d ' ')"
  budget=$(((MAX_BODY - used - 2000) / count))
  [ "$budget" -ge 1000 ] || budget=1000

  while IFS=$'\t' read -r name image; do
    [ -n "$name" ] || continue
    {
      printf '<details><summary>Trivy report: <code>%s</code></summary>\n\n' "${image:-$name}"
      printf '```\n'
      render_report "$REPORT_DIR/$name.txt" "$budget"
      printf '```\n\n</details>\n\n'
    } >>"$out"
  done <"$MANIFEST"

  if [ -n "$RUN_URL" ]; then
    echo "The complete reports are attached to the [workflow run]($RUN_URL) as the \`$ARTIFACT_NAME\` artifact." >>"$out"
  fi
}

body="$(mktemp)"
trap 'rm -f "$body"' EXIT

issue_number="$(find_open_issue)"

if [ -n "$issue_number" ]; then
  log "updating existing tracking issue #$issue_number"
  render_body comment "$body"
  gh issue comment "$issue_number" --repo "$REPO" --body-file "$body"
  issue_url="$SERVER_URL/$REPO/issues/$issue_number"
else
  log "opening a new tracking issue"
  render_body create "$body"
  create_args=(issue create --repo "$REPO" --title "$TITLE" --body-file "$body")
  if [ -n "$usable_labels" ]; then
    create_args+=(--label "$usable_labels")
  fi
  issue_url="$(gh "${create_args[@]}")"
fi

log "tracking issue: $issue_url"

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "issue-url=$issue_url" >>"$GITHUB_OUTPUT"
fi

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  echo "Trivy tracking issue: $issue_url" >>"$GITHUB_STEP_SUMMARY"
fi
