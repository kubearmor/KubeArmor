#!/bin/bash
# Copyright 2021 Authors of KubeArmor
# SPDX-License-Identifier: Apache-2.0


ARMOR_HOME=`dirname $(realpath "$0")`/..

rm -rf $ARMOR_HOME/build/KubeArmor
rm -rf $ARMOR_HOME/build/GKE
rm -rf $ARMOR_HOME/build/protobuf

rm -f $ARMOR_HOME/build/KubeArmorPolicy.yaml
rm -f $ARMOR_HOME/build/KubeArmorHostPolicy.yaml
