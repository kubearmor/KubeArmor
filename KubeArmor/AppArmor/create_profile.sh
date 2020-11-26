#!/bin/bash

ARMOR_PROFILE=`dirname $(realpath "$0")`

if [ -z $1 ]; then
    echo "Usage: $0 [profile_name]"
    exit 1
fi

cp $ARMOR_PROFILE/apparmor-default /etc/apparmor.d/$1 && sed -i "s/apparmor-default/$1/g" /etc/apparmor.d/$1 && apparmor_parser -r -W /etc/apparmor.d/$1
