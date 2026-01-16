# SPDX-License-Identifier: Apache-2.0
# Copyright 2026  Authors of KubeArmor
#!/usr/bin/env bash

set -e

if [ ! -e "/sys/kernel/btf/vmlinux" ]; then
    # compile BPF programs
    make -C /opt/kubearmor/BPF/
fi

# update karmor SELinux module if BPFLSM is not present 
lsm_file="/sys/kernel/security/lsm"
bpf="bpf"
if ! grep -q "$bpf" "$lsm_file"; then
    if [ -x "$(command -v semanage)" ]; then
        # old karmor SELinux module
        /opt/kubearmor/templates/uninstall.sh

        # new karmor SELinux module
        /opt/kubearmor/templates/install.sh

    fi
fi

# start kubearmor.service
/bin/systemctl daemon-reload
/bin/systemctl start kubearmor.service
