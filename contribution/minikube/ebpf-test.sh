#!/bin/bash

# run BCC tools
minikube ssh -- docker run --rm --privileged -v /lib/modules:/lib/modules:ro -v /usr/src:/usr/src:ro -v /etc/localtime:/etc/localtime:ro --workdir /usr/share/bcc/tools zlim/bcc ./execsnoop
