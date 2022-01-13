#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

. /etc/os-release

if [ "$ID" == "ubuntu" ]; then
    # install virtualbox
    wget -q https://www.virtualbox.org/download/oracle_vbox_2016.asc -O- | sudo apt-key add -
    wget -q https://www.virtualbox.org/download/oracle_vbox.asc -O- | sudo apt-key add -
    sudo add-apt-repository "deb [arch=amd64] http://download.virtualbox.org/virtualbox/debian $(lsb_release -cs) contrib"
    sudo apt-get update
    sudo apt-get -y install virtualbox-6.1

    # install vagrant
    wget https://releases.hashicorp.com/vagrant/2.2.9/vagrant_2.2.9_x86_64.deb
    sudo dpkg -i vagrant_2.2.9_x86_64.deb
    sudo apt-get -y install nfs-kernel-server
    rm vagrant_2.2.9_x86_64.deb

    # install vagrant plugins
    vagrant plugin install vagrant-vbguest
    vagrant plugin install vagrant-reload
    vagrant plugin install vagrant-disksize

    echo "Please reboot the machine"
elif [ "$ID" == "centos" ]; then
    # install virtualbox
    sudo dnf -y install wget elfutils-libelf-devel dkms kernel-devel
    sudo wget https://download.virtualbox.org/virtualbox/rpm/el/virtualbox.repo -O /etc/yum.repos.d/virtualbox.repo
    sudo dnf -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
    sudo dnf -y install binutils kernel-devel kernel-headers gcc make patch glibc-headers glibc-devel libgomp dkms
    sudo dnf install -y VirtualBox-6.1
    sudo usermod -aG vboxusers $USER

    # install vagrant
    sudo dnf config-manager --add-repo=https://rpm.releases.hashicorp.com/RHEL/hashicorp.repo
    sudo dnf -y install vagrant

    # install vagrant plugins
    vagrant plugin install vagrant-vbguest
    vagrant plugin install vagrant-reload
    vagrant plugin install vagrant-disksize

    echo "Please reboot the machine"
fi
