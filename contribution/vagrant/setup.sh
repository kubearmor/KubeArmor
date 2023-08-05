#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

. /etc/os-release

if [ "$ID" == "centos" ]; then
    if [ ! -x "$(command -v vboxmanage)" ]; then
        # install virtualbox
        sudo dnf -y install wget elfutils-libelf-devel dkms kernel-devel
        sudo wget https://download.virtualbox.org/virtualbox/rpm/el/virtualbox.repo -O /etc/yum.repos.d/virtualbox.repo
        sudo dnf -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
        sudo dnf -y install binutils kernel-devel kernel-headers gcc make patch glibc-headers glibc-devel libgomp dkms
        sudo dnf install -y VirtualBox-6.1
        sudo usermod -aG vboxusers $USER
    fi

    if [ ! -x "$(command -v vagrant)" ]; then
        # install vagrant
        sudo yum install -y yum-utils
        sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/RHEL/hashicorp.repo
        sudo yum -y install vagrant
    fi

    # install vagrant plugins
    vagrant plugin install vagrant-vbguest
    vagrant plugin install vagrant-reload

    echo "Please reboot the machine"
elif [ "$ID" == "ubuntu" ]; then
    if [ ! -x "$(command -v vboxmanage)" ]; then
        # install virtualbox
        wget -q https://www.virtualbox.org/download/oracle_vbox_2016.asc -O- | sudo apt-key add -
        wget -q https://www.virtualbox.org/download/oracle_vbox.asc -O- | sudo apt-key add -
        sudo add-apt-repository "deb [arch=amd64] http://download.virtualbox.org/virtualbox/debian $(lsb_release -cs) contrib"
        sudo apt-get update
        sudo apt-get -y install virtualbox-6.1
    fi

    if [ ! -x "$(command -v vagrant)" ]; then
        # install vagrant
        wget -O- https://apt.releases.hashicorp.com/gpg | gpg --dearmor | sudo tee /usr/share/keyrings/hashicorp-archive-keyring.gpg
        echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
        sudo apt update && sudo apt install vagrant
    fi

    # install vagrant plugins
    vagrant plugin install vagrant-vbguest
    vagrant plugin install vagrant-reload

    echo "Please reboot the machine."
elif [ "$(uname -om)" == "Darwin arm64" ]; then
  if [ `command -v brew` ]; then
    # Install vagrant
    if [ ! `command -v vagrant` ]; then
      echo "Installing vagrant..."
      brew install hashicorp/tap/hashicorp-vagrant
    fi

    vagrant plugin install vagrant-vmware-desktop

    # Install VMware Fusion
    if [ ! -d /Applications/VMware\ Fusion.app/ ]; then
        echo "Installing VMware Fusion and utils..."
        brew install --cask vmware-fusion
        brew install --cask vagrant-vmware-utility
        echo
        echo "Please Configure VMware Fusion License"
        # Wait so that user can see the above message
        sleep 2
        open /opt/homebrew/Caskroom/vmware-fusion/*/VMware\ Fusion.app
    fi
  else
    echo "Please install brew or find out how to install VirtualBox/VMware and Vagrant on your OS."
  fi
else
    echo "Please find out how to install VirtualBox and Vagrant on your OS."
fi
