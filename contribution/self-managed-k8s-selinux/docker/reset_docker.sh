#!/bin/bash

docker rm -f `docker ps -aq` 2> /dev/null
docker rmi -f `docker images -aq` 2> /dev/null
docker volume rm -f `docker volume ls -q` 2> /dev/null
docker network prune -f

sudo systemctl stop docker

sudo umount /var/lib/docker/volumes 2> /dev/null
sudo rm -rf /var/lib/docker

sudo systemctl start docker
