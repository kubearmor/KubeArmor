#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

[[ "$REPO" == "" ]] && REPO="$REPO_OWNER/kubearmor"

[[ "$PLATFORMS" == "" ]] && PLATFORMS="linux/amd64,linux/arm64/v8"

[[ "$STABLE_VERSION" != "" ]] && STABEL_LABEL="--label stabel-version=$STABLE_VERSION"

# set LABEL
unset LABEL
[[ "$GITHUB_SHA" != "" ]] && LABEL="--label github_sha=$GITHUB_SHA"

VERSION=latest

# check version
if [ ! -z $1 ]; then
    VERSION="$1"
fi

realpath() {
    CURR=$PWD

    cd "$(dirname "$0")"
    LINK=$(readlink "$(basename "$0")")

    while [ "$LINK" ]; do
        cd "$(dirname "$LINK")"
        LINK=$(readlink "$(basename "$1")")
    done

    REALPATH="$PWD/$(basename "$1")"
    echo "$REALPATH"

    cd $CURR
}

ARMOR_HOME=`dirname $(realpath "$0")`/..
cd $ARMOR_HOME/build
pwd

# push $REPO
echo "[INFO] Pushing $REPO:$VERSION"
cd $ARMOR_HOME/..; docker buildx build --metadata-file kubearmor.json --platform $PLATFORMS -t $REPO:$VERSION -f Dockerfile --push $LABEL $STABEL_LABEL .

[[ $? -ne 0 ]] && echo "[FAILED] Failed to push $REPO:$VERSION" && exit 1
echo "[PASSED] Pushed $REPO:$VERSION"

# push $REPO-init
echo "[INFO] Pushing $REPO-init:$VERSION"
cd $ARMOR_HOME/..; docker buildx build --metadata-file kubearmor-init.json --platform $PLATFORMS -t $REPO-init:$VERSION -f Dockerfile.init --push $LABEL $STABEL_LABEL .

[[ $? -ne 0 ]] && echo "[FAILED] Failed to push $REPO-init:$VERSION" && exit 1
echo "[PASSED] Pushed $REPO-init:$VERSION"

exit 0
