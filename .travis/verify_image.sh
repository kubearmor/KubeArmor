#!/bin/bash

ARMOR_HOME=`dirname $(realpath "$0")`/..

# build KubeArmor image

$ARMOR_HOME/KubeArmor/build/build_kubearmor.sh test

# check KubeArmor image

IMAGE_NAME="accuknox/kubearmor:test"
TEST_IMAGE=`docker images --format '{{.Repository}}:{{.Tag}}' | grep $IMAGE_NAME`

echo "Check KubeArmor Image"
echo ">> Expected:" $IMAGE_NAME ", Received:" $TEST_IMAGE

if [ "$IMAGE_NAME" != "$TEST_IMAGE" ]; then
    echo "[FAILED] Not built $IMAGE_NAME"
    exit 1
else
    echo "[PASSED] Built $IMAGE_NAME"
    exit 0
fi
