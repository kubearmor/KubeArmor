#!/bin/bash

grep "KubeArmor" /etc/apparmor.d/* 2> /dev/null | awk -F':' '{print $1}' | xargs -I {} apparmor_parser -R {} 2> /dev/null
grep "KubeArmor" /etc/apparmor.d/* 2> /dev/null | awk -F':' '{print $1}' | xargs -I {} rm -f {}
