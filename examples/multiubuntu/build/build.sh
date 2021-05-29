#!/bin/bash

# remove old images
docker images | grep ubuntu-w-utils | awk '{print $3}' | xargs -I {} docker rmi -f {} 2> /dev/null

# create new images
docker build --tag 0x010/ubuntu-w-utils:latest .

# push new images
docker push 0x010/ubuntu-w-utils:latest
