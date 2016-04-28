#!/bin/bash
sudo apt-get install python python-pip python-dev libffi-dev libssl-dev
sudo apt-get install mongodb git
cd cuckoo
sudo pip install -r requirements.txt

sudo apt-get install virtualbox && \
sudo usermod -a -G vboxusers cuckoo && \
sudo usermod -a -G libvirtd cuckoo && \
sudo ip link set vboxnet0 up
sudo ip addr add 192.168.56.1/24 dev vboxnet0
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
