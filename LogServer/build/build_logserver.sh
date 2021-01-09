#!/bin/bash

SERVER_PATH=`dirname $(realpath "$0")`/..
cd $SERVER_PATH/build

# check version

VERSION=latest

if [ ! -z $1 ]; then
    VERSION=$1
fi

# remove old images

docker images | grep accuknox/kubearmor-logserver | awk '{print $3}' | xargs -I {} docker rmi -f {} 2> /dev/null

echo "[INFO] Removed existing accuknox/kubearmor-logserver images"

# remove old files (just in case)

$SERVER_PATH/build/clean_source_files.sh

echo "[INFO] Removed source files just in case"

# copy files to build

$SERVER_PATH/build/copy_source_files.sh

echo "[INFO] Copied new source files"

# build a new image

echo "[INFO] Building accuknox/kubearmor-logserver:$VERSION"
docker build -t accuknox/kubearmor-logserver:$VERSION  . -f $SERVER_PATH/build/Dockerfile.logserver

if [ $? == 0 ]; then
    echo "[PASSED] Built accuknox/kubearmor-logserver:$VERSION"
    # exit 0
else
    echo "[FAILED] Failed to build accuknox/kubearmor-logserver:$VERSION"
    exit 1
fi

# remove old files

$SERVER_PATH/build/clean_source_files.sh

echo "[INFO] Removed source files"
exit 0
