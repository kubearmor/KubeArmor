#!/bin/bash

IMAGE_NAME="kubearmor/kubearmor:test"
TEST_IMAGE=`docker images --format '{{.Repository}}:{{.Tag}}' | grep $IMAGE_NAME`

echo "Expected:" $IMAGE_NAME ", Received:" $TEST_IMAGE

if [ "$IMAGE_NAME" == "$TEST_IMAGE" ]; then
    exit 0
else
    exit 1
fi
