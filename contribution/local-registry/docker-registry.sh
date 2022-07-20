# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

# deploy docker-registry
docker run -d -p 0.0.0.0:5000:5000 --restart=always --name registry registry:2

# create daemon.json
REGIP=$(ip -o route get to 8.8.8.8 | sed -n 's/.*src \([0-9.]\+\).*/\1/p')
sudo cat <<EOF > daemon.json
{
    "insecure-registries" : ["$REGIP:5000"]
}
EOF

# replace daemon.json
if [[ -f /etc/docker/daemon.json ]] && [[ ! -f /etc/docker/daemon.json.bak ]]; then
    sudo mv /etc/docker/daemon.json /etc/docker/daemon.json.bak
fi
sudo mv daemon.json /etc/docker/daemon.json
sudo cat /etc/docker/daemon.json

# restart docker.service
sudo systemctl restart docker.service
