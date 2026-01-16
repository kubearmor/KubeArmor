#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026  Authors of KubeArmor

sudo systemctl stop crio.service

sudo yum remove cri-o

sudo rm -rf /etc/crictl.yaml
sudo rm -rf /var/lib/crio
