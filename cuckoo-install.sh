#!/bin/bash
cd ../
sudo apt-get install python-sqlalchemy
sudo apt-get install python-dpkt python-jinja2 python-magic python-pymongo python-libvirt python-bottle python-pefile ssdeep
sudo apt-get install build-essential git libpcre3 libpcre3-dev libpcre++-dev
sudo git clone https://github.com/kbandla/pydeep.git pydeep
cd pydeep
sudo python setup.py build
sudo python setup.py install
sudo apt-get install virtualbox && \
sudo usermod -a -G vboxusers cuckoo && \
sudo usermod -a -G libvirtd cuckoo && \
sudo apt-get install python python-pip python-dev libffi-dev libssl-dev
sudo apt-get install mongodb
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
cd /home/cuckoo and git clone https://github.com/cuckoosandbox/cuckoo.git cuckoo
cd cuckoo && sudo pip install -r requirements.txt
sudo pip install requests
sudo pip install bson
cd /home/cuckoo/cuckoo && \
sudo VBoxManage hostonlyif create
sudo ip link set vboxnet0 up
sudo ip addr add 192.168.56.1/24 dev vboxnet0
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
