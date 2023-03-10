# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor
#!/usr/bin/env bash

set -e

# compile BPF programs
make -C /opt/kubearmor/BPF/

# update karmor SELinux module
if [ -x "$(command -v semanage)" ]; then
    # old karmor SELinux module
    /opt/kubearmor/templates/uninstall.sh

    # new karmor SELinux module
    /opt/kubearmor/templates/install.sh
fi

# start kubearmor.service
/bin/systemctl daemon-reload
/bin/systemctl start kubearmor.service

# Set default GRPC listening port for kubearmor as environment variable
echo "export KUBEARMOR_SERVICE=:32767" >> ~/.bashrc
source ~/.bashrc