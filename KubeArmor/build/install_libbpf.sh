#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

err_not_found() {
	echo "$1 not found";
	exit 1;
}

[ -z "$1" ] && { echo "Usage: $(basename $0) INSTALLPATH"; exit 1; }

# tooling
GIT="$(which git)"
[ -f "$GIT" ] || err_not_found "git"

CC="$(which gcc)"
[ -f "$CC" ] || err_not_found "gcc"

BPFTOOL="$(which bpftool)"
[ -f "$BPFTOOL" ] || err_not_found "bpftool"

# C libbpf
LIBPPFREP="https://github.com/libbpf/libbpf.git"
LIBBPFDIR="$(realpath ~/libbpf)"
LIBBPFSRC="$LIBBPFDIR/src"
LIBBPFINC="$(realpath $1/include)"

[ ! -d "$LIBBPFDIR" ] && \
	$GIT clone $LIBPPFREP $LIBBPFDIR

CFLAGS="-g -O2 -Werror -Wall -fpie"

# dependencies: zlib, libelf
CC=$CC CFLAGS=$CFLAGS \
	make -C $LIBBPFSRC \
		BUILD_STATIC_ONLY=1 \
		OBJDIR=./build \
		DESTDIR=$LIBBPFINC \
		INCLUDEDIR= LIBDIR= UAPIDIR= \
		install

# vmlinux header file
BTFFILE="/sys/kernel/btf/vmlinux"
[ -f "$BTFFILE" ] || err_not_found $BTFFILE

VMLINUXH="$LIBBPFINC/vmlinux.h"
$BPFTOOL btf dump file $BTFFILE format c > $VMLINUXH

# cleaning
rm -rf $LIBBPFDIR
