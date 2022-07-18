#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

KRNDIR=""

FILE=/media/root/etc/os-release
if [ -f "$FILE" ]; then
    . $FILE
    if [ "$ID" == "cos" ]; then
        echo "* COS detected (build ${BUILD_ID}), downloading COS kernel headers"
        . /KubeArmor/GKE/download_cos_kernel_headers.sh
        KRNDIR=/KubeArmor/GKE/kernel/usr/src/linux-headers-$(uname -r)
        echo $KRNDIR
    fi
fi

cd /KubeArmor/BPF

if [[ -n "$KRNDIR" ]]; then
    make KRNDIR=$KRNDIR
else
    make
fi

cp *.bpf.o /opt/kubearmor/BPF/
