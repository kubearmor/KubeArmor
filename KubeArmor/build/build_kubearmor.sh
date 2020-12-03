#!/bin/bash

ARMOR_HOME=`dirname $(realpath "$0")`/..

# remove old images
docker images | grep kubearmor | awk '{print $3}' | xargs -I {} docker rmi -f {} 2> /dev/null

echo "[INFO] Removed existing KubeArmor images"

# remove old files (just in case)
$ARMOR_HOME/build/clean_source_files.sh

echo "[INFO] Removed source files just in case"

# copy files to build
$ARMOR_HOME/build/copy_source_files.sh

echo "[INFO] Copied new source files"

cd $ARMOR_HOME/build

if [ -z $1 ]; then
    echo "[INFO] Building accuknox/kubearmor:latest"
    docker build -t accuknox/kubearmor:latest  . -f $ARMOR_HOME/build/Dockerfile.kubearmor
else
    echo "[INFO] Building accuknox/kubearmor:$1"
    docker build -t accuknox/kubearmor:$1  . -f $ARMOR_HOME/build/Dockerfile.kubearmor
fi

if [ $? == 0 ]; then
    echo "[PASSED] Built the KubeArmor image"
else
    echo "[FAILED] Failed to build the KubeArmor image"
    exit 1
fi

# remove old files
$ARMOR_HOME/build/clean_source_files.sh

echo "[INFO] Removed source files"
exit 0
