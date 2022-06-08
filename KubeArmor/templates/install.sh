#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

realpath() {
    CURR=$PWD

    cd "$(dirname "$0")"
    LINK=$(readlink "$(basename "$0")")

    while [ "$LINK" ]; do
        cd "$(dirname "$LINK")"
        LINK=$(readlink "$(basename "$1")")
    done

    REALPATH="$PWD/$(basename "$1")"
    echo "$REALPATH"
}

MOD_DIR=`dirname $(realpath "$0")`
cd $MOD_DIR

if [ -z $1 ]; then
    exit 1
elif [ "$1" != "karmorG" -a "$1" != "karmorA" -a "$1" != "karmorB" ]; then
    exit 1
fi

MOD=$1

if [ "$MOD" == "karmorG" ]; then
    # copy karmorG to $MOD
    cp default/karmorG.fc $MOD.fc
    cp default/karmorG.if $MOD.if
    cp default/karmorG.te $MOD.te

elif [ "$MOD" == "karmorA" ]; then
    # copy karmorA to $MOD
    cp default/karmorA.fc $MOD.fc
    cp default/karmorA.if $MOD.if
    cp default/karmorA.te $MOD.te

    # ## == ##

    tmpfile1="/tmp/$RANDOM.tmp"
    tmpfile2="/tmp/$RANDOM.tmp"

    sesearch -A | grep -v ":file" | grep -v "karmor" | grep -v ":True" | grep -v ":False" | grep -v "domain" | cut -d" " -f 3- | sort -u > $tmpfile1

    cat $tmpfile1 | grep -v "^$" | while read line;
    do
        if [[ "$line" != *"type"* ]]; then
            echo "allow karmorA_t $line" >> $tmpfile2
        fi
    done

    echo "require {" >> $MOD.te

    cat $tmpfile2 | grep -v "^$" | awk '{print $3}' | awk -F':' '{print $1}' | sort -u | while read line;
    do
        echo "    type $line;" >> $MOD.te
    done

    echo "}" >> $MOD.te
    echo >> $MOD.te

    cat $tmpfile2 | grep -v "^$" | sort -u | while read line;
    do
        echo $line >> $MOD.te
    done

    rm -f $tmpfile1 $tmpfile2

    ## == ##

elif [ "$MOD" == "karmorB" ]; then
    # copy karmorB to $MOD
    cp default/karmorB.fc $MOD.fc
    cp default/karmorB.if $MOD.if
    cp default/karmorB.te $MOD.te

    # ## == ##

    tmpfile1="/tmp/$RANDOM.tmp"
    tmpfile2="/tmp/$RANDOM.tmp"

    sesearch -A | grep -v "karmor" | grep -v ":True" | grep -v ":False" | grep -v "domain" | cut -d" " -f 3- | sort -u > $tmpfile1

    cat $tmpfile1 | grep -v "^$" | while read line;
    do
        if [[ "$line" != *"type"* ]]; then
            echo "allow karmorB_t $line" >> $tmpfile2
        fi
    done

    echo "require {" >> $MOD.te

    cat $tmpfile2 | grep -v "^$" | awk '{print $3}' | awk -F':' '{print $1}' | sort -u | while read line;
    do
        echo "    type $line;" >> $MOD.te
    done

    echo "}" >> $MOD.te
    echo >> $MOD.te

    cat $tmpfile2 | grep -v "^$" | sort -u | while read line;
    do
        echo $line >> $MOD.te
    done

    rm -f $tmpfile1 $tmpfile2

    ## == ##
fi

# compile and insert selinux module
make -f /usr/share/selinux/devel/Makefile $MOD.pp && semodule -i $MOD.pp
if [ $? != 0 ]; then
    # remove temp files
    rm -rf $MOD.fc $MOD.if $MOD.te $MOD.pp tmp

    echo "Failed to install $MOD SELinux module"
    exit 1
fi

# remove temp files
rm -rf $MOD.fc $MOD.if $MOD.te $MOD.pp tmp

exit 0
