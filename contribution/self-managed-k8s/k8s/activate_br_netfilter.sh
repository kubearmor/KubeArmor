#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

# activate br_netfilter
sudo modprobe br_netfilter
sudo bash -c "echo '1' > /proc/sys/net/bridge/bridge-nf-call-iptables"
sudo bash -c "echo 'net.bridge.bridge-nf-call-iptables=1' >> /etc/sysctl.conf"
