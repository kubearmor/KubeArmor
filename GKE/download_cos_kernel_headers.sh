#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

cd /KubeArmor/GKE

# get OS info
. /media/root/etc/os-release

# remove old kernel headers (just in case)
rm -rf kernel-headers.tgz kernel

# download kernel headers
wget https://accuknox.kr/cos/$BUILD_ID/kernel-headers.tgz

# make a directory
mkdir kernel

# extract kernel headers to the kernel
tar xfz kernel-headers.tgz -C kernel/

# remove downloaded files
rm -f kernel-headers.tgz
