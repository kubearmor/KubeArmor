#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Authors of KubeArmor

set -euo pipefail
umask 077

if [[ $# -ne 1 || -z "${1:-}" ]]; then
  echo "Usage: $0 <new-output-directory>" >&2
  exit 1
fi

fixture_dir=$1
if [[ -e "$fixture_dir" || -L "$fixture_dir" ]]; then
  echo "Fixture output directory must not already exist: $fixture_dir" >&2
  exit 1
fi
mkdir -- "$fixture_dir"

for plane in log management; do
  plane_dir="$fixture_dir/$plane"
  mkdir -- "$plane_dir"

  # The self provider expects a PKCS#1 RSA CA key.
  openssl genrsa -traditional -out "$plane_dir/ca.key" 2048
  openssl req -new -x509 -sha256 -days 2 \
    -key "$plane_dir/ca.key" -out "$plane_dir/ca.crt" \
    -subj "/CN=kubearmor-systemd-$plane-ca" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

  leaf_serial=1
  for role in server client; do
    openssl genrsa -traditional -out "$plane_dir/$role.key" 2048
    openssl req -new -sha256 -key "$plane_dir/$role.key" \
      -subj "/CN=kubearmor-systemd-$plane-$role" |
      openssl x509 -req -sha256 -days 2 -set_serial "$leaf_serial" \
        -CA "$plane_dir/ca.crt" -CAkey "$plane_dir/ca.key" \
        -out "$plane_dir/$role.crt" \
        -extfile <(
          printf '%s\n' \
            'basicConstraints=critical,CA:FALSE' \
            'keyUsage=critical,digitalSignature,keyEncipherment' \
            "extendedKeyUsage=${role}Auth"
          if [[ "$role" == server ]]; then
            printf '%s\n' 'subjectAltName=DNS:localhost'
          fi
        )
    leaf_serial=$((leaf_serial + 1))
  done
done
