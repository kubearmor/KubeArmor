#!/bin/bash

SRV_HOME=`dirname $(realpath "$0")`/..

# remove old images
docker images | grep kubearmor-logserver | awk '{print $3}' | xargs -I {} docker rmi -f {} 2> /dev/null

echo "[INFO] Removed existing KubeArmor images"

cd $SRV_HOME/build

# remove old files (just in case)
$SRV_HOME/build/clean_source_files.sh

echo "[INFO] Removed source files just in case"

# copy files to build
$SRV_HOME/build/copy_source_files.sh

echo "[INFO] Copied new source files"

if [ -z $1 ]; then
    echo "[INFO] Building accuknox/kubearmor-logserver:latest"
    docker build -t accuknox/kubearmor-logserver:latest  . -f $SRV_HOME/build/Dockerfile.logserver
else
    echo "[INFO] Building accuknox/kubearmor-logserver:$1"
    docker build -t accuknox/kubearmor-logserver:$1  . -f $SRV_HOME/build/Dockerfile.logserver
fi

if [ $? == 0 ]; then
    echo "[PASSED] Built the KubeArmor-LogServer image"
else
    echo "[FAILED] Failed to build the KubeArmor-LogServer image"
    exit 1
fi

# remove old files
$SRV_HOME/build/clean_source_files.sh

echo "[INFO] Removed source files"
exit 0
