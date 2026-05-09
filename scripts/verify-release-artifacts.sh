#!/usr/bin/env bash
# Verify KubeArmor release artifact signatures
#
# Usage: ./scripts/verify-release-artifacts.sh v1.6.15 [kubearmor/KubeArmor]

set -euo pipefail

VERSION="${1:-}"
REPO="${2:-kubearmor/KubeArmor}"

if [[ -z "${VERSION}" ]]; then
  echo "Usage: $0 <version-tag> [repo]"
  echo "Example: $0 v1.6.15"
  echo "Example: $0 v1.6.15 YOUR_USERNAME/KubeArmor"
  exit 1
fi

# Strip leading 'v' for goreleaser artifact naming
VERSION_NO_V="${VERSION#v}"
ARCH="amd64"
ARTIFACT="kubearmor_${VERSION_NO_V}_linux-${ARCH}.tar.gz"
BUNDLE="${ARTIFACT}.sigstore.json"
PROVENANCE="kubearmor.intoto.jsonl"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"

TMPDIR=$(mktemp -d)
trap "rm -rf ${TMPDIR}" EXIT
cd "${TMPDIR}"

echo "Verifying: ${VERSION}"
echo ""
curl -sSfLO "${BASE_URL}/${ARTIFACT}"
curl -sSfLO "${BASE_URL}/${BUNDLE}"

# Download provenance if it exists
if curl -sSfL "${BASE_URL}/${PROVENANCE}" -o "${PROVENANCE}" 2>/dev/null; then
  PROVENANCE_EXISTS=true
else
  PROVENANCE_EXISTS=false
fi

echo ""
echo "Verifying cosign signature..."
cosign verify-blob \
  "${ARTIFACT}" \
  --bundle "${BUNDLE}" \
  --certificate-identity-regexp "https://github.com/${REPO}/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
echo "✓ Signature verified"

if [[ "${PROVENANCE_EXISTS}" == "true" ]]; then
  echo ""
  echo "Verifying SLSA provenance..."

  if ! command -v slsa-verifier &>/dev/null; then
    go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest
  fi

  slsa-verifier verify-artifact "${ARTIFACT}" \
    --provenance-path "${PROVENANCE}" \
    --source-uri "github.com/${REPO}" \
    --source-tag "${VERSION}"

  echo "✓ Provenance verified"
else
  echo ""
  echo "Note: No provenance file found for ${VERSION}"
fi

echo ""
echo "Verification complete"
