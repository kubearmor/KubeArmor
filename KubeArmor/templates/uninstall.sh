#!/bin/bash

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

    cd $CURR
}

CURR_DIR=`dirname $(realpath "$0")`
cd $CURR_DIR

MOD="karmor"

if [ ! -z $1 ]; then
    MOD=$1
fi

# remove SELinux module
semodule -r $MOD

