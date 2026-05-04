#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Authors of KubeArmor

# remove docker
sudo dnf remove docker-ce docker-ce-cli containerd.io

# remove any associated files
sudo rm -rf /var/lib/docker
sudo rm -rf /var/lib/containerd
