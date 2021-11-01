#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

# Refer to https://minikube.sigs.k8s.io/docs/tutorials/ebpf_tools_in_minikube

# run BCC tools
minikube ssh -- docker run --rm --privileged -v /lib/modules:/lib/modules:ro -v /usr/src:/usr/src:ro -v /etc/localtime:/etc/localtime:ro --workdir /usr/share/bcc/tools zlim/bcc ./execsnoop
