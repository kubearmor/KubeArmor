#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Authors of KubeArmor

# Summarizes the per-component Trivy scan step outcomes for the ci-trivy-scan
# and ci-trivy-scan-ubi workflows.
#
# Input (environment):
#   TRIVY_COMPONENTS  newline separated records of "name|image|outcome|enabled".
#                     "outcome" is the GitHub Actions outcome of the scan step and
#                     "enabled" is "true" when the component was actually built.
#   TRIVY_REPORT_DIR  directory holding the "<name>.txt" Trivy reports
#                     (default: trivy-reports)
#
# Output:
#   - a human readable summary on stdout and, when running in CI, in the job summary
#   - the "vulnerable" and "failed_components" step outputs
#   - "$TRIVY_REPORT_DIR/failed-components.tsv" listing "name<TAB>image" for every
#     failing component, later consumed by trivy-report-issue.sh

set -euo pipefail

REPORT_DIR="${TRIVY_REPORT_DIR:-trivy-reports}"
: "${TRIVY_COMPONENTS:?TRIVY_COMPONENTS must be set}"

mkdir -p "$REPORT_DIR"
manifest="$REPORT_DIR/failed-components.tsv"
: >"$manifest"

summary="$(mktemp)"
trap 'rm -f "$summary"' EXIT

failed_components=""
vulnerable="false"

{
  echo "## Trivy scan results"
  echo
  echo "| Component | Image | Result |"
  echo "| --- | --- | --- |"
} >>"$summary"

# Trim the surrounding whitespace that YAML block scalars leave behind.
trim() {
  printf '%s' "${1:-}" | tr -d '[:space:]'
}

while IFS='|' read -r name image outcome enabled; do
  name="$(trim "${name:-}")"
  [ -n "$name" ] || continue
  image="$(trim "${image:-}")"
  outcome="$(trim "${outcome:-}")"
  enabled="$(trim "${enabled:-}")"

  if [ "$enabled" != "true" ]; then
    printf "| %s | \`%s\` | :fast_forward: skipped (not built) |\n" "$name" "$image" >>"$summary"
    continue
  fi

  case "$outcome" in
  failure)
    printf "| %s | \`%s\` | :x: vulnerabilities found |\n" "$name" "$image" >>"$summary"
    printf '%s\t%s\n' "$name" "$image" >>"$manifest"
    failed_components="${failed_components:+$failed_components }$name"
    vulnerable="true"
    ;;
  success)
    printf "| %s | \`%s\` | :white_check_mark: passed |\n" "$name" "$image" >>"$summary"
    ;;
  *)
    printf "| %s | \`%s\` | :warning: scan did not run (%s) |\n" \
      "$name" "$image" "${outcome:-unknown}" >>"$summary"
    ;;
  esac
done <<EOF
$TRIVY_COMPONENTS
EOF

# Keep the reports visible in the job log: with "output" set, trivy-action writes
# the tables to files instead of printing them.
for report in "$REPORT_DIR"/*.txt; do
  [ -f "$report" ] || continue
  echo "=============================================================="
  echo "Trivy report: $(basename "$report")"
  echo "=============================================================="
  cat "$report"
  echo
done

cat "$summary"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  cat "$summary" >>"$GITHUB_STEP_SUMMARY"
fi

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "vulnerable=$vulnerable"
    echo "failed_components=$failed_components"
  } >>"$GITHUB_OUTPUT"
fi

if [ "$vulnerable" = "true" ]; then
  echo "Trivy found vulnerabilities in: $failed_components"
else
  echo "All Trivy scans passed."
fi
