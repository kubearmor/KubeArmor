#!/bin/bash

ARMOR_HOME=`dirname $(realpath "$0")`/..

# copy files to build
cp -r $ARMOR_HOME/audit/ $ARMOR_HOME/build/
cp -r $ARMOR_HOME/Auditd/ $ARMOR_HOME/build/
cp -r $ARMOR_HOME/BPF/ $ARMOR_HOME/build/
cp -r $ARMOR_HOME/common/ $ARMOR_HOME/build/
cp -r $ARMOR_HOME/core/ $ARMOR_HOME/build/
cp -r $ARMOR_HOME/discovery/ $ARMOR_HOME/build/
cp -r $ARMOR_HOME/enforcer/ $ARMOR_HOME/build/
cp -r $ARMOR_HOME/feeder/ $ARMOR_HOME/build/
cp -r $ARMOR_HOME/log/ $ARMOR_HOME/build/
cp -r $ARMOR_HOME/monitor/ $ARMOR_HOME/build/
cp -r $ARMOR_HOME/types/ $ARMOR_HOME/build/
cp    $ARMOR_HOME/go.mod $ARMOR_HOME/build/
cp    $ARMOR_HOME/main.go $ARMOR_HOME/build/

# copy GKE files
cp -r $ARMOR_HOME/../GKE/ $ARMOR_HOME/build/
