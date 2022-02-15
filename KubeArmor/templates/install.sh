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

MOD="karmor" # default

if [ ! -z $1 ]; then
    MOD=$1
fi

if [ "$MOD" == "karmor" ]; then
    cd default

    # compile and insert selinux module
    make -f /usr/share/selinux/devel/Makefile $MOD.pp && semodule -i $MOD.pp
    if [ $? != 0 ]; then
        # remove temp files
        rm -rf $MOD.pp tmp

        echo "Failed to install $MOD SELinux module"
        exit 1
    fi

    # remove temp files
    rm -rf $MOD.pp tmp
else
    MOD=$1

    # copy karmorX to $MOD
    cp karmorX.fc $MOD.fc
    cp karmorX.if $MOD.if
    cp karmorX.te $MOD.te

    ## == ##

    tmpfile1="/tmp/$RANDOM.tmp"
    tmpfile2="/tmp/$RANDOM.tmp"
    tmpfile3="/tmp/$RANDOM.tmp"

    sesearch -A | grep -e "allow user_t " -e "allow user_usertype " | grep -v "karmor" | sed 's/allow user_usertype /allow user_t /g' | sort -u > $tmpfile1
    semanage fcontext -l > $tmpfile3

    echo > $tmpfile2

    cat $tmpfile1 | grep -v "^$" | while read line;
    do
        echo $line | awk '{print $3}' | awk -F ':' '{print $1}' >> $tmpfile2
    done

    echo "require {" >> $MOD.te

    cat $tmpfile2 | grep -v "^$" | sort -u | while read line;
    do
        grep $line $tmpfile3 > /dev/null 2>&1
        if [ $? != 0 ]; then
            if [[ "$line" != *"_type"* ]] || [[ "$line" == "file_type" ]] || [[ "$line" == "application_domain_type" ]] || [[ "$line" == "application_exec_type" ]]; then
                continue
            fi
        fi
        echo "    type $line;" >> $MOD.te
    done

    echo "}" >> $MOD.te
    echo >> $MOD.te

    cat $tmpfile1 | while read line;
    do
        label=$(echo $line | awk '{print $3}' | awk -F ':' '{print $1}')

        grep $label $tmpfile3 > /dev/null 2>&1
        if [ $? != 0 ]; then
            if [[ "$label" != *"_type"* ]] || [[ "$label" == "file_type" ]] || [[ "$line" == "application_domain_type" ]] || [[ "$line" == "application_exec_type" ]]; then
                continue
            fi
        fi

        if [[ "$line" == *"]:"* ]]; then
            continue
        else
            echo $line | sed 's/allow user_t /allow karmorX_t /g' >> $MOD.te
        fi
    done

    rm -f $tmpfile1 $tmpfile2 $tmpfile3

    ## == ##

    # replace karmorX with $MOD
    sed -i "s/karmorX/$MOD/g" $MOD.te

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
fi

exit 0
