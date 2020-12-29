#!/bin/bash

rm -f /KubeArmor/audit/audit.log && ln -s /var/log/audit/buffer.*.log /KubeArmor/audit/audit.log
