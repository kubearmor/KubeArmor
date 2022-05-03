#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

cd /KubeArmor/BPF
make
cp *.bpf.o /opt/kubearmor/BPF/
