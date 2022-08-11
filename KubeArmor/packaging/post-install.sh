# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor
#!/usr/bin/env bash

set -e

<<<<<<< HEAD
make -C /opt/kubearmor/BPF/

=======
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
>>>>>>> 079f699e9d18f32712e3e0c64b288334f60079a4
/bin/systemctl daemon-reload
/bin/systemctl start kubearmor.service
