#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

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

echo "Please reboot the machine"
