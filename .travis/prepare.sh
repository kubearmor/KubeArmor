#!/bin/bash

# install kernel-headers
sudo apt-get update
sudo apt-get install -y linux-headers-$(uname -r)
