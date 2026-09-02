#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Authors of KubeArmor
#
# Verify that KubeArmor builds reproducibly.
#
# Usage:
#   bash scripts/verify-reproducible-build.sh [--check-env] [<tag-or-commit>]
#
# With no arguments: builds HEAD twice and verifies the two binaries are identical.
# With a tag/commit: checks out that revision first, then builds twice and compares.
# With --check-env:  only validates the build environment and exits.
#
# The build itself is delegated to `make -C KubeArmor build-reproducible` so that the
# deterministic build flags live in exactly one place (the Makefile) and cannot drift
# from what releases (.goreleaser.yaml) and CI use.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KUBEARMOR_DIR="$REPO_ROOT/KubeArmor"
BUILD_OUT_1="$(mktemp -d)/kubearmor-1"
BUILD_OUT_2="$(mktemp -d)/kubearmor-2"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { printf '  %s\n' "$*"; }

cleanup() { rm -f "$BUILD_OUT_1" "$BUILD_OUT_2"; }
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Environment check
# ---------------------------------------------------------------------------
check_env() {
    local ok=true

    echo "Checking build environment..."

    # Go
    if ! command -v go &>/dev/null; then
        red "FAIL: 'go' not found in PATH"
        ok=false
    else
        local go_version required_version
        go_version=$(go version | awk '{print $3}' | sed 's/go//')
        required_version=$(grep '^go ' "$KUBEARMOR_DIR/go.mod" | awk '{print $2}')
        if [[ "$go_version" != "$required_version"* ]]; then
            red "FAIL: Go version mismatch — found $go_version, need $required_version"
            info "Install the correct version: go install golang.org/dl/go${required_version}@latest"
            ok=false
        else
            green "OK:   Go $go_version"
        fi
    fi

    # Git
    if ! command -v git &>/dev/null; then
        red "FAIL: 'git' not found in PATH"; ok=false
    else
        green "OK:   $(git --version)"
    fi

    # make
    if ! command -v make &>/dev/null; then
        red "FAIL: 'make' not found in PATH"; ok=false
    else
        green "OK:   $(make --version | head -1)"
    fi

    # OS architecture
    local arch; arch=$(uname -m)
    if [[ "$arch" != "x86_64" ]]; then
        red "WARN: Architecture is $arch — official releases target x86_64"
    else
        green "OK:   Architecture $arch"
    fi

    # CGO
    if [[ "${CGO_ENABLED:-}" == "1" ]]; then
        red "WARN: CGO_ENABLED=1 — reproducible builds require CGO_ENABLED=0"
    else
        green "OK:   CGO_ENABLED=0 (default)"
    fi

    # Dirty worktree (uncommitted changes alter git describe / commit timestamp)
    if ! git -C "$REPO_ROOT" diff --quiet HEAD 2>/dev/null; then
        red "WARN: Working tree has uncommitted changes — these affect the build"
    else
        green "OK:   Working tree is clean"
    fi

    if [[ "$ok" != "true" ]]; then
        echo; red "Environment check failed. Fix the issues above before building."
        exit 1
    fi

    echo; green "Environment looks good."
}

# ---------------------------------------------------------------------------
# Reproducible build (delegates to the Makefile — single source of truth)
# ---------------------------------------------------------------------------
build_once() {
    local output="$1"
    make -C "$KUBEARMOR_DIR" build-reproducible >/dev/null
    cp "$KUBEARMOR_DIR/kubearmor" "$output"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    local check_env_only=false
    local target_ref=""

    for arg in "$@"; do
        case "$arg" in
            --check-env) check_env_only=true ;;
            *)           target_ref="$arg" ;;
        esac
    done

    check_env
    [[ "$check_env_only" == "true" ]] && exit 0

    if [[ -n "$target_ref" ]]; then
        echo "Checking out $target_ref..."
        git -C "$REPO_ROOT" checkout "$target_ref"
    fi

    local commit
    commit=$(git -C "$REPO_ROOT" rev-parse --short HEAD)
    echo "Verifying reproducibility for commit $commit"

    echo; echo "Build 1/2..."; build_once "$BUILD_OUT_1"
    echo "Build 2/2..."; build_once "$BUILD_OUT_2"

    local sum1 sum2
    sum1=$(sha256sum "$BUILD_OUT_1" | awk '{print $1}')
    sum2=$(sha256sum "$BUILD_OUT_2" | awk '{print $1}')

    echo
    echo "SHA-256 build 1: $sum1"
    echo "SHA-256 build 2: $sum2"
    echo

    if [[ "$sum1" == "$sum2" ]]; then
        green "VERIFICATION SUCCESS: both builds produced the same binary."
        echo
        info "This is the same binary the release pipeline (.goreleaser.yaml) produces"
        info "for a clean checkout of this commit. To verify a published release, compare"
        info "this checksum against the release's *_checksums.txt asset on GitHub."
        exit 0
    else
        red "VERIFICATION FAILED: builds produced different binaries."
        info "See docs/build-reproducibility/verification-guide.md for troubleshooting."
        exit 1
    fi
}

main "$@"
