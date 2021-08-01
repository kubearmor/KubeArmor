#!/bin/bash
# Copyright 2021 Authors of KubeArmor
# SPDX-License-Identifier: Apache-2.0


set -eo pipefail

die() {
  echo "$*" 1>&2
  exit 1
}

need() {
  command -v "$1" &>/dev/null || die "Binary '$1' is missing but required"
}

need "jq"
need "curl"
need "kubectl"

TARGET_NAMEPSACE="$1"
TOKEN=$(kubectl get secrets -o jsonpath="{.items[?(@.metadata.annotations['kubernetes\.io/service-account\.name']=='default')].data.token}"|base64 --decode)
API_SERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')

test -n "$TARGET_NAMEPSACE" || die "Missing arguments: $0 <namespace>"
test -n "$TOKEN" || die "failed to get kubernetes token"
test -n "$API_SERVER" || die "failed to get kubernets api address"

echo "trying to remove finalizers of namespace '$TARGET_NAMEPSACE'..."

kubectl get namespace "$TARGET_NAMEPSACE" -o json | \
jq 'del(.spec.finalizers[] | select(. == "kubernetes"))' | \
curl -k -X PUT --insecure "$API_SERVER/api/v1/namespaces/$TARGET_NAMEPSACE/finalize" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  --data-binary @-
