#!/bin/bash

ARMOR_HOME=`dirname $(realpath "$0")`/..
cd $ARMOR_HOME/build

# check version

VERSION=latest

if [ ! -z $1 ]; then
    VERSION=$1
fi

# remove old images

docker images | grep kubearmor | awk '{print $3}' | xargs -I {} docker rmi -f {} 2> /dev/null

echo "[INFO] Removed existing accuknox/kubearmor images"

# remove old files (just in case)

$ARMOR_HOME/build/clean_source_files.sh

echo "[INFO] Removed source files just in case"

# copy files to build

$ARMOR_HOME/build/copy_source_files.sh

echo "[INFO] Copied new source files"

echo "[INFO] Building accuknox/kubearmor:$VERSION"
docker build -t accuknox/kubearmor:$VERSION  . -f $ARMOR_HOME/build/Dockerfile.kubearmor

if [ $? == 0 ]; then
    echo "[PASSED] Built accuknox/kubearmor:$VERSION"
else
    echo "[FAILED] Failed to build accuknox/kubearmor:$VERSION"
    exit 1
fi

# remove old files

$ARMOR_HOME/build/clean_source_files.sh

echo "[INFO] Removed source files"
exit 0
