#!/bin/bash

. /media/root/etc/os-release

cd /KubeArmor/GKE

# remove old kernel headers (just in case)
rm -rf kernel-headers.tgz kernel

# download kernel headers
wget https://0x010.com/cos/$BUILD_ID/kernel-headers.tgz

# make a directory
mkdir kernel

# extract kernel headers to the kernel
tar xfz kernel-headers.tgz -C kernel/

# remove downloaded files
rm -f kernel-headers.tgz
