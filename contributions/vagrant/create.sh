#!/bin/bash

# create ssh keys
if [ ! -f ~/.ssh/id_rsa.pub ]; then
    ssh-keygen
fi

# create a VM
vagrant up
