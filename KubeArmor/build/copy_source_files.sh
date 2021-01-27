#!/bin/bash

ARMOR_HOME=`dirname $(realpath "$0")`/..

# copy files to build
mkdir -p $ARMOR_HOME/build/KubeArmor
cp -r $ARMOR_HOME/BPF/ $ARMOR_HOME/build/KubeArmor/
cp -r $ARMOR_HOME/common/ $ARMOR_HOME/build/KubeArmor/
cp -r $ARMOR_HOME/core/ $ARMOR_HOME/build/KubeArmor/
cp -r $ARMOR_HOME/discovery/ $ARMOR_HOME/build/KubeArmor/
cp -r $ARMOR_HOME/enforcer/ $ARMOR_HOME/build/KubeArmor/
cp -r $ARMOR_HOME/feeder/ $ARMOR_HOME/build/KubeArmor/
cp -r $ARMOR_HOME/log/ $ARMOR_HOME/build/KubeArmor/
cp -r $ARMOR_HOME/monitor/ $ARMOR_HOME/build/KubeArmor/
cp -r $ARMOR_HOME/types/ $ARMOR_HOME/build/KubeArmor/
cp $ARMOR_HOME/go.mod $ARMOR_HOME/build/KubeArmor/
cp $ARMOR_HOME/main.go $ARMOR_HOME/build/KubeArmor/

# copy patch.sh
cp $ARMOR_HOME/build/patch.sh $ARMOR_HOME/build/KubeArmor/

# copy GKE files
cp -r $ARMOR_HOME/../GKE $ARMOR_HOME/build/

# copy protobuf
cp -r $ARMOR_HOME/../protobuf $ARMOR_HOME/build/
