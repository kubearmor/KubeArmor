# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

FROM ubuntu:18.04

RUN apt-get update

RUN apt-get install -y net-tools iputils-ping telnet ssh tcpdump nmap dsniff arping
RUN apt-get install -y curl iperf3 netperf ethtool python-scapy python-pip
RUN apt-get install -y iptables bridge-utils apache2 vim

RUN apt-get clean
RUN apt-get autoremove -y
RUN rm -rf /var/lib/{apt,dpkg,cache,log}/

RUN pip install flask
ADD flask/http_test.py /
COPY entrypoint.sh /entrypoint.sh

RUN echo "secret file" >> secret.txt
RUN echo "plain file" >> plain.txt

RUN mkdir /credentials
RUN echo "password file" >> /credentials/password
RUN echo "token file" >> /credentials/token

RUN mkdir -p /credentials/keys
RUN echo "cert file" >> /credentials/keys/cert.ca
RUN echo "key file" >> /credentials/keys/priv.key

RUN useradd --create-home --shell /bin/bash user1
RUN echo 'user1:passwd1' | chpasswd
COPY hello /home/user1/hello
RUN chown user1:user1 /home/user1/hello

RUN echo "secret file user1" >> /home/user1/secret_data1.txt
RUN chown user1:user1 /home/user1/secret_data1.txt

RUN mkdir -p /home/user1/dir1
RUN chown user1:user1 /home/user1/dir1
RUN echo "key file 1" >> /home/user1/dir1/key1.txt
RUN chown user1:user1 /home/user1/dir1/key1.txt

RUN echo "other file" >> /home/user1/otherfile.txt
RUN chown user1:user1 /home/user1/otherfile.txt

COPY readwriter /readwrite
COPY readwriter /home/user1/readwrite
RUN chown user1:user1 /home/user1/readwrite  

CMD [ "/entrypoint.sh" ]
