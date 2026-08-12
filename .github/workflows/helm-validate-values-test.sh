#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Authors of KubeArmor

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"
script="$repo_root/.github/workflows/helm-validate-values.sh"
bash_bin="$(command -v bash)"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

assert_contains() {
	local haystack="$1"
	local needle="$2"

	if [[ "$haystack" != *"$needle"* ]]; then
		echo "expected output to contain: $needle" >&2
		echo "$haystack" >&2
		exit 1
	fi
}

run_missing_helm_test() {
	local bindir="$tmpdir/missing/bin"
	mkdir -p "$bindir"
	ln -s "$(command -v rm)" "$bindir/rm"

	set +e
	local output
	output="$(PATH="$bindir" "$bash_bin" "$script" 2>&1)"
	local status=$?
	set -e

	if [[ $status -eq 0 ]]; then
		echo "expected missing-helm test to fail" >&2
		exit 1
	fi

	assert_contains "$output" "helm is required to validate environment specific templates."
}

run_failed_helm_test() {
	local bindir="$tmpdir/failing/bin"
	mkdir -p "$bindir"
	ln -s "$(command -v rm)" "$bindir/rm"
	cat > "$bindir/helm" <<EOF
#!$bash_bin
echo "simulated helm failure" >&2
exit 2
EOF
	chmod +x "$bindir/helm"

	set +e
	local output
	output="$(PATH="$bindir" "$bash_bin" "$script" 2>&1)"
	local status=$?
	set -e

	if [[ $status -eq 0 ]]; then
		echo "expected failing-helm test to fail" >&2
		exit 1
	fi

	assert_contains "$output" "Generating templates for docker..."
	assert_contains "$output" "simulated helm failure"
}

run_success_test() {
	local bindir="$tmpdir/success/bin"
	mkdir -p "$bindir"
	ln -s "$(command -v rm)" "$bindir/rm"
	cat > "$bindir/helm" <<EOF
#!$bash_bin
printf 'kind: ConfigMap\nmetadata:\n  name: rendered\n'
EOF
	chmod +x "$bindir/helm"

	local output
	output="$(cd "$repo_root" && PATH="$bindir" "$bash_bin" "$script" 2>&1)"

	assert_contains "$output" "Validated environment specific templates!"

	for env in docker crio k3s microk8s minikube GKE BottleRocket EKS generic; do
		if [[ -e "$repo_root/$env.yml" ]]; then
			echo "expected $env.yml to be removed" >&2
			exit 1
		fi
	done
}

run_missing_helm_test
run_failed_helm_test
run_success_test
