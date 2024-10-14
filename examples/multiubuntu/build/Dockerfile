# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

FROM ubuntu:22.04 as builder

RUN apt-get update && apt install -y gcc python3 pipx python3-venv
COPY helloworld/ /helloworld/
COPY readwrite/ /readwrite/

RUN gcc -o hello /helloworld/hello.c
RUN gcc -o readwriter /readwrite/readwrite.c

RUN pipx install fee

ENV PATH=$PATH:/root/.local/bin

RUN fee /bin/ls > /ls.py


FROM ubuntu:22.04

RUN apt-get update

RUN apt-get install -y net-tools iputils-ping telnet ssh tcpdump nmap dsniff arping
RUN apt-get install -y curl iperf3 netperf ethtool python3 python3-scapy python3-flask pipx python3-venv
RUN apt-get install -y iptables bridge-utils apache2 vim

RUN apt-get clean
RUN apt-get autoremove -y
RUN rm -rf /var/lib/{apt,dpkg,cache,log}/


RUN ln -s $(which python3) /usr/bin/python
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
COPY --from=builder /hello /home/user1/hello
RUN chown user1:user1 /home/user1/hello

RUN echo "secret file user1" >> /home/user1/secret_data1.txt
RUN chown user1:user1 /home/user1/secret_data1.txt

RUN mkdir -p /home/user1/dir1
RUN chown user1:user1 /home/user1/dir1
RUN echo "key file 1" >> /home/user1/dir1/key1.txt
RUN chown user1:user1 /home/user1/dir1/key1.txt

RUN echo "other file" >> /home/user1/otherfile.txt
RUN chown user1:user1 /home/user1/otherfile.txt

COPY --from=builder /readwriter /home/user1/readwrite
RUN chown user1:user1 /home/user1/readwrite

COPY --from=builder /ls.py /ls.py

CMD [ "/entrypoint.sh" ]