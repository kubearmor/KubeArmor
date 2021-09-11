#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

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

# check version

VERSION=latest

if [ ! -z $1 ]; then
    VERSION=$1
fi

# remove old images
docker images | grep kubearmor | awk '{print $3}' | xargs -I {} docker rmi -f {} 2> /dev/null

echo "[INFO] Removed existing kubearmor/kubearmor images"

# remove old files (just in case)
$ARMOR_HOME/build/clean_source_files.sh

echo "[INFO] Removed source files just in case"

# copy files to build
$ARMOR_HOME/build/copy_source_files.sh

echo "[INFO] Copied new source files"

# build a new image
echo "[INFO] Building kubearmor/kubearmor:$VERSION"
docker build -t kubearmor/kubearmor:$VERSION  . -f $ARMOR_HOME/build/Dockerfile

if [ $? != 0 ]; then
    echo "[FAILED] Failed to build kubearmor/kubearmor:$VERSION"
    exit 1
else
    echo "[PASSED] Built kubearmor/kubearmor:$VERSION"
fi

# remove copied files
$ARMOR_HOME/build/clean_source_files.sh

echo "[INFO] Removed source files"
exit 0
