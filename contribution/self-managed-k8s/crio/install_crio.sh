#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Authors of KubeArmor

. /etc/os-release

if [ "$NAME" != "Ubuntu" ]; then
    echo "Support Ubuntu 18.xx, 20.xx"
    exit
fi

OS="x${NAME}_${VERSION_ID}"

# install cri-o corresponding to the latest k3s version
VERSION=$(curl -w '%{url_effective}' -L -s -S https://update.k3s.io/v1-release/channels/stable -o /dev/null | sed -e 's|.*/||' | cut -d '.' -f1,2)
echo "Installing CRI-O version $VERSION"

curl -fsSL https://download.opensuse.org/repositories/isv:/cri-o:/stable:/$VERSION/deb/Release.key |
    sudo gpg --dearmor -o /etc/apt/keyrings/cri-o-apt-keyring.gpg

echo "deb [signed-by=/etc/apt/keyrings/cri-o-apt-keyring.gpg] https://download.opensuse.org/repositories/isv:/cri-o:/stable:/$VERSION/deb/ /" |
    sudo tee /etc/apt/sources.list.d/cri-o.list

# install
sudo apt-get update
sudo apt-get install -y cri-o
sudo dpkg -i --force-overwrite /var/cache/apt/archives/cri-o_*.deb

# this option is not supported in ubuntu 18.04
if [ "$VERSION_ID" == "18.04" ]; then
    sudo sed -i 's/,metacopy=on//g' /etc/containers/storage.conf
fi

git clone https://github.com/containernetworking/plugins
cd plugins
git checkout $(git tag -l | sort -V | tail -n 1)
./build_linux.sh # or build_windows.sh

sudo mkdir -p /opt/cni/bin
sudo cp bin/* /opt/cni/bin/

# CNI configuration - https://github.com/k3s-io/k3s/issues/13344
sudo mkdir -p /etc/cni/net.d
sudo mkdir -p /etc/crio/crio.conf.d

sudo tee /etc/crio/crio.conf.d/20-cni.conf >/dev/null <<'EOF'
[crio.network]
plugin_dirs = [ "/var/lib/rancher/k3s/data/cni" ]
network_dir = "/etc/cni/net.d"
EOF

sudo tee /etc/cni/net.d/10-crio-bridge.conflist >/dev/null <<'EOF'
{
  "cniVersion": "1.0.0",
  "name": "crio",
  "plugins": [
    {
      "type": "bridge",
      "bridge": "cni0",
      "isGateway": true,
      "ipMasq": true,
      "hairpinMode": true,
      "ipam": {
        "type": "host-local",
        "ranges": [
          [
            {
              "subnet": "10.85.0.0/16"
            }
          ]
        ],
        "routes": [
          {
            "dst": "0.0.0.0/0"
          }
        ]
      }
    },
    {
      "type": "portmap",
      "capabilities": {
        "portMappings": true
      }
    },
    {
      "type": "bandwidth",
      "capabilities": {
        "bandwidth": true
      }
    }
  ]
}
EOF

sudo systemctl daemon-reload
sudo systemctl start crio.service
