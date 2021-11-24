#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

BPFTOOL=/usr/sbin/bpftool
TMPZIP=/tmp/linux.zip
LINUXSRC=https://github.com/torvalds/linux/archive/refs/heads/master.zip

wget -nv $LINUXSRC -O $TMPZIP
7z x $TMPZIP -o/tmp
make -C /tmp/linux-master/tools/bpf/bpftool/ bootstrap
cp /tmp/linux-master/tools/bpf/bpftool/bootstrap/bpftool $BPFTOOL
