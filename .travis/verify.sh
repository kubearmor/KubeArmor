#!/bin/bash

IMAGE_NAME="accuknox/kubearmor:test"
TEST_IMAGE=`docker images --format '{{.Repository}}:{{.Tag}}' | grep $IMAGE_NAME`

echo "Check KubeArmor Image"
echo ">> Expected:" $IMAGE_NAME ", Received:" $TEST_IMAGE

if [ "$IMAGE_NAME" != "$TEST_IMAGE" ]; then
    echo "[FAILED] Not built $IMAGE_NAME"
    exit 1
else
    echo "[PASSED] Built $IMAGE_NAME"
fi

IMAGE_NAME="accuknox/kubearmor-cos-auditd:test"
TEST_IMAGE=`docker images --format '{{.Repository}}:{{.Tag}}' | grep $IMAGE_NAME`

echo "Check KubeArmor-COS-Auditd Image"
echo ">> Expected:" $IMAGE_NAME ", Received:" $TEST_IMAGE

if [ "$IMAGE_NAME" != "$TEST_IMAGE" ]; then
    echo "[FAILED] Not built $IMAGE_NAME"
    exit 1
else
    echo "[PASSED] Built $IMAGE_NAME"
fi

IMAGE_NAME="accuknox/kubearmor-logserver:test"
TEST_IMAGE=`docker images --format '{{.Repository}}:{{.Tag}}' | grep $IMAGE_NAME`

echo "Check KubeArmor-LogServer Image"
echo ">> Expected:" $IMAGE_NAME ", Received:" $TEST_IMAGE

if [ "$IMAGE_NAME" != "$TEST_IMAGE" ]; then
    echo "[FAILED] Not built $IMAGE_NAME"
    exit 1
else
    echo "[PASSED] Built $IMAGE_NAME"
fi

exit 0
