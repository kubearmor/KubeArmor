#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

# Cleanup function
cleanup() {
  echo "Performing cleanup..."
  
  /usr/local/bin/k3s-killall.sh
  
  /usr/local/bin/k3s-uninstall.sh
  
  docker system prune -a -f
  
  if command -v podman &> /dev/null; then
    sudo podman system prune -a -f
  fi

  # rm -rf /home/vagrant/actions-runner/_work/KubeArmor

  echo "Cleanup complete."
}
# Invoke the cleanup function
cleanup