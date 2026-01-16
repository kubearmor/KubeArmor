#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026  Authors of KubeArmor

cd /KubeArmor/BPF
make clean

if [[ -n "$KRNDIR" ]]; then
    make KRNDIR=$KRNDIR
else
    make
fi

cp *.bpf.o /opt/kubearmor/BPF/
