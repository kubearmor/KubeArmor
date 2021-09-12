#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

# remove old images
docker images | grep ubuntu-w-utils | awk '{print $3}' | xargs -I {} docker rmi -f {} 2> /dev/null

# create new images
docker build --tag kubearmor/ubuntu-w-utils:0.1 --tag kubearmor/ubuntu-w-utils:latest .

# push new images
docker push kubearmor/ubuntu-w-utils:0.1
docker push kubearmor/ubuntu-w-utils:latest
