#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

[[ "$REPO" == "" ]] && REPO="kubearmor/kubearmor"

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

VERSION=latest
ENABLE_PPROF=true

# check version
if [ ! -z $1 ]; then
    VERSION=$1
fi

# check ENABLE_PPROF
if [ ! -z $2 ]; then
    ENABLE_PPROF=$2
fi

export DOCKER_BUILDKIT=1

# remove old images
docker images | grep kubearmor | awk '{print $3}' | xargs -I {} docker rmi -f {} 2> /dev/null
echo "[INFO] Removed existing $REPO images"

# set LABEL
unset LABEL
[[ "$GITHUB_SHA" != "" ]] && LABEL="--label github_sha=$GITHUB_SHA"

# build a kubearmor image
DTAG="-t $REPO:$VERSION"
echo "[INFO] Building $DTAG"
cd $ARMOR_HOME/..; docker build $DTAG -f Dockerfile --target kubearmor . $LABEL -e ENABLE_PPROF=false

if [ $? != 0 ]; then
    echo "[FAILED] Failed to build $REPO:$VERSION"
    exit 1
fi
echo "[PASSED] Built $REPO:$VERSION"

# build a kubearmor-init image
DTAGINI="-t $REPO-init:$VERSION"
echo "[INFO] Building $DTAGINI"
cd $ARMOR_HOME/..; docker build $DTAGINI -f Dockerfile.init --target kubearmor-init . $LABEL

if [ $? != 0 ]; then
    echo "[FAILED] Failed to build $REPO-init:$VERSION"
    exit 1
fi
echo "[PASSED] Built $REPO-init:$VERSION"

# build a debug kubearmor image
DTAG="-t $REPO:$VERSION" + "-debug"
echo "[INFO] Building $DTAG"
cd $ARMOR_HOME/..; docker build $DTAG -f Dockerfile --target kubearmor . $LABEL -e ENABLE_PPROF=$ENABLE_PPROF

if [ $? != 0 ]; then
    echo "[FAILED] Failed to build $REPO:$VERSION-debug"
    exit 1
fi
echo "[PASSED] Built $REPO:$VERSION-debug"

exit 0
