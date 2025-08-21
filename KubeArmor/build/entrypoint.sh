#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Authors of KubeArmor

set -e

../build/compile.sh

/KubeArmor/deployHook
