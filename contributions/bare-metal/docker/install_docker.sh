#!/bin/bash

. /etc/os-release

if [ "$NAME" != "Ubuntu" ]; then
    echo "Support Ubuntu 16.xx, 18.xx, 20.xx"
    exit
fi

# update repo
sudo apt-get update

# add GPG key
sudo apt-get install -y curl
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -

# add Docker repository
sudo apt-get install -y software-properties-common
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"

# update the Docker repo
sudo apt-get update

# make sure we install Docker from the Docker repo
sudo apt-cache policy docker-ce

# install Docker (the oldest version among the versions that Ubuntu supports)
case "$VERSION" in
"16."*)
    sudo apt-get install -y docker-ce=17.12.1~ce-0~ubuntu;;
"18."*)
    sudo apt-get install -y docker-ce=18.03.1~ce~3-0~ubuntu;;
"20.04"*)
    sudo apt-get install -y docker-ce=5:19.03.9~3-0~ubuntu-focal;;
"20.10"*)
    sudo apt-get install -y docker-ce=5:20.10.0~3-0~ubuntu-groovy;;
*)
    echo "Support Ubuntu 16.xx, 18.xx, 20.xx"; exit;;
esac

# add user to docker
if [ "$(hostname)" == "kubearmor-dev" ]; then
    sudo usermod -aG docker vagrant
else
    sudo usermod -aG docker $USER
fi

# bypass to run docker command
sudo chmod 666 /var/run/docker.sock

# install docker-compose
sudo curl -sL https://github.com/docker/compose/releases/download/1.18.0/docker-compose-`uname -s`-`uname -m` -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
