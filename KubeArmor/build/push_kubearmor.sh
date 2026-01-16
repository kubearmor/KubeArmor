#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026  Authors of KubeArmor

[[ "$REPO" == "" ]] && REPO="kubearmor/kubearmor"

[[ "$PLATFORMS" == "" ]] && PLATFORMS="linux/amd64,linux/arm64/v8"

[[ "$STABLE_VERSION" != "" ]] && STABEL_LABEL="--label stabel-version=$STABLE_VERSION"

UBIREPO="kubearmor/kubearmor-ubi"

# set LABEL
unset LABEL
[[ "$GITHUB_SHA" != "" ]] && LABEL="--label github_sha=$GITHUB_SHA"

VERSION=latest

# check version
if [ ! -z $1 ]; then
    VERSION="$1"
fi

if [ ! -z "$2" ]; then
    if [[ "$2" == "--push" || "$2" == "--load" ]]; then
        BUILD_MODE="$2"
    else
        echo "[ERROR] Invalid second argument: must be --push or --load"
        exit 1
    fi
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
cd $ARMOR_HOME/..; docker buildx build --metadata-file kubearmor.json --platform $PLATFORMS --target kubearmor -t $REPO:$VERSION -f Dockerfile $BUILD_MODE $LABEL $STABEL_LABEL .

[[ $? -ne 0 ]] && echo "[FAILED] Failed to push $REPO:$VERSION" && exit 1
echo "[PASSED] Pushed $REPO:$VERSION"

# push $REPO-init
echo "[INFO] Pushing $REPO-init:$VERSION"
cd $ARMOR_HOME/..; docker buildx build --metadata-file kubearmor-init.json --platform $PLATFORMS --build-arg VERSION=$VERSION -t $REPO-init:$VERSION -f Dockerfile.init $BUILD_MODE $LABEL $STABEL_LABEL .

[[ $? -ne 0 ]] && echo "[FAILED] Failed to push $REPO-init:$VERSION" && exit 1
echo "[PASSED] Pushed $REPO-init:$VERSION"

# push $UBIREPO
echo "[INFO] Pushing $UBIREPO:$VERSION"
cd $ARMOR_HOME/..; docker buildx build --metadata-file kubearmor-ubi.json --platform $PLATFORMS --build-arg VERSION=$VERSION --target kubearmor-ubi -t $UBIREPO:$VERSION -f Dockerfile $BUILD_MODE $LABEL $STABEL_LABEL .

[[ $? -ne 0 ]] && echo "[FAILED] Failed to push $UBIREPO:$VERSION" && exit 1
echo "[PASSED] Pushed $UBIREPO:$VERSION"

exit 0
