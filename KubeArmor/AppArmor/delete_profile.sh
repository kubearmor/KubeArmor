#!/bin/bash

if [ -z $1 ]; then
    echo "Usage: $0 [profile_name]"
    exit
fi

apparmor_parser -R /etc/apparmor.d/$1 && rm /etc/apparmor.d/$1
