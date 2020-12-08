#!/bin/bash

ARMOR_HOME=`dirname $(realpath "$0")`/..

rm -rf $ARMOR_HOME/build/AppArmor
rm -rf $ARMOR_HOME/build/apparmor.d
rm -rf $ARMOR_HOME/build/audit
rm -rf $ARMOR_HOME/build/Auditd
rm -rf $ARMOR_HOME/build/BPF
rm -rf $ARMOR_HOME/build/common
rm -rf $ARMOR_HOME/build/core
rm -rf $ARMOR_HOME/build/discovery
rm -rf $ARMOR_HOME/build/enforcer
rm -rf $ARMOR_HOME/build/feeder
rm -rf $ARMOR_HOME/build/GKE
rm -rf $ARMOR_HOME/build/log
rm -rf $ARMOR_HOME/build/monitor
rm -rf $ARMOR_HOME/build/types
rm -f  $ARMOR_HOME/build/go.mod
rm -f  $ARMOR_HOME/build/main.go
