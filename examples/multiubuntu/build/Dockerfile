# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

FROM ubuntu:18.04

RUN apt-get update

RUN apt-get install -y net-tools iputils-ping telnet ssh tcpdump nmap dsniff
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

CMD [ "/entrypoint.sh" ]
