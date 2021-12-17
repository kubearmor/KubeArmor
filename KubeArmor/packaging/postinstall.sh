# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor
#!/usr/bin/env bash

set -e

/bin/systemctl daemon-reload
/bin/systemctl start kubearmor.service
