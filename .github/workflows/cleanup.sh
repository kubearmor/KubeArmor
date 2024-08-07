#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

# Cleanup function
cleanup() {
  echo "Performing cleanup..."
  
  if [ -f /usr/local/bin/k3s-killall.sh ]; then
    /usr/local/bin/k3s-killall.sh
  else
    echo "/usr/local/bin/k3s-killall.sh not found. Skipping..."
  fi
  
  if [ -f /usr/local/bin/k3s-uninstall.sh ]; then
    /usr/local/bin/k3s-uninstall.sh
  else
    echo "/usr/local/bin/k3s-uninstall.sh not found. Skipping..."
  fi
  
  docker system prune -a -f
  
  sudo podman system prune -a -f
  
  # rm -rf /home/vagrant/actions-runner/_work/KubeArmor

  echo "Cleanup complete."
}

# Invoke the cleanup function
cleanup
