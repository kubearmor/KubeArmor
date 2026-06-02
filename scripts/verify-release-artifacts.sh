#!/usr/bin/env bash

set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <owner/repo> <tag>"
  echo "Example: $0 sodiq-code/KubeArmor v0.0.1-signed-test"
  exit 1
fi

REPO="$1"
TAG="$2"
WORKDIR="$(mktemp -d)"

cleanup() {
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

echo "Downloading release assets for $REPO@$TAG"
gh release download "$TAG" -R "$REPO" -D "$WORKDIR"

cd "$WORKDIR"

if [[ ! -f kubearmor-linux-amd64.tar.gz ]] || [[ ! -f kubearmor-linux-amd64.tar.gz.sigstore.json ]]; then
  echo "Required binary assets not found"
  exit 2
fi

if [[ ! -f multiple.intoto.jsonl-linux-amd64 ]]; then
  echo "Combined in-toto JSONL asset not found"
  exit 2
fi

echo "Verifying binary SLSA attestation"
cosign verify-blob-attestation \
  --bundle kubearmor-linux-amd64.tar.gz.sigstore.json \
  --type slsaprovenance \
  --certificate-identity-regexp ".*" \
  --certificate-oidc-issuer-regexp ".*" \
  kubearmor-linux-amd64.tar.gz > /dev/null

echo "Validating combined in-toto JSONL payloads"
while IFS= read -r line; do
  payload="$(echo "$line" | jq -r '.payload')"
  echo "$payload" | base64 -d | jq -e '.predicateType == "https://slsa.dev/provenance/v1"' > /dev/null
done < multiple.intoto.jsonl-linux-amd64

echo "Release artifact verification passed for $REPO@$TAG"