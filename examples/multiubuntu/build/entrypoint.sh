#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

# run http server (8000)
/http_test.py 8000 &

# run http server (8080)
/http_test.py 8080 &

# run iperf3 (5001)
iperf3 -s -p 5001 &

# run iperf3 (5101)
iperf3 -s -p 5101 &

# run iperf3 (5201)
iperf3 -s -p 5201 &

# run netserver
netserver

# start apache2
service apache2 start

# infinite loop
/usr/bin/tail -f /dev/null
