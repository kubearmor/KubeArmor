#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

sudo systemctl stop crio.service

sudo apt purge -y cri-o cri-o-runc
sudo apt autoremove -y --purge cri-o cri-o-runc

sudo rm -rf /etc/crictl.yaml
sudo rm -rf /var/lib/crio

# check storage.conf
