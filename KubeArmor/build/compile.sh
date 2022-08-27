#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

cd /KubeArmor/BPF
make clean

if [[ -n "$KRNDIR" ]]; then
    make KRNDIR=$KRNDIR
else
    make
fi

cp *.bpf.o /opt/kubearmor/BPF/
