# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor
#!/usr/bin/env bash

set -e

make -C /opt/kubearmor/BPF/

/bin/systemctl daemon-reload
/bin/systemctl start kubearmor.service
