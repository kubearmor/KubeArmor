#!/bin/bash
# Copyright 2021 Authors of KubeArmor
# SPDX-License-Identifier: Apache-2.0


ARMOR_HOME=`dirname $(realpath "$0")`/..
cd $ARMOR_HOME/build

# check version

VERSION=latest

if [ ! -z $1 ]; then
    VERSION=$1
fi

# remove old images

docker images | grep kubearmor-selinux | awk '{print $3}' | xargs -I {} docker rmi -f {} 2> /dev/null

echo "[INFO] Removed existing kubearmor/kubearmor-selinux images"

# remove old files (just in case)

$ARMOR_HOME/build/clean_source_files.sh

echo "[INFO] Removed source files just in case"

# copy files to build

$ARMOR_HOME/build/copy_source_files.sh

echo "[INFO] Copied new source files"

echo "[INFO] Building kubearmor/kubearmor-selinux:$VERSION"
docker build -t kubearmor/kubearmor-selinux:$VERSION  . -f $ARMOR_HOME/build/Dockerfile.kubearmor.selinux

if [ $? != 0 ]; then
    echo "[FAILED] Failed to build kubearmor/kubearmor-selinux:$VERSION"
    exit 1
else
    echo "[PASSED] Built kubearmor/kubearmor-selinux:$VERSION"
fi

# remove old files

$ARMOR_HOME/build/clean_source_files.sh

echo "[INFO] Removed source files"
exit 0
