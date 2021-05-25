#!/bin/bash

ARMOR_HOME=`dirname $(realpath "$0")`/..

rm -rf $ARMOR_HOME/build/KubeArmor
rm -rf $ARMOR_HOME/build/GKE
rm -rf $ARMOR_HOME/build/protobuf

rm -rf $ARMOR_HOME/build/LogClient
rm -rf $ARMOR_HOME/build/MySQLClient
rm -rf $ARMOR_HOME/build/KafkaClient
