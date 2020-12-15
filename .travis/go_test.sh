#!/bin/bash

KBA_HOME=`dirname $(realpath "$0")`/..

cd $KBA_HOME/KubeArmor
#go test -v

cd $KBA_HOME/LogServer
go test -v

exit 0
