#!/usr/bin/env bash

cuckoo_path_base="/home/cuckoo/"
cuckoo_user="cuckoo"

# From Cuckoo Documentation
sudo apt-get install -y python python-dev python-pip qemu-kvm libvirt-bin ubuntu-vm-builder bridge-utils python-libvirt tcpdump libfuzzy-dev ssdeep
# Extra for Ubuntu 14.04.3 LTS
sudo apt-get install -y libffi-dev libssl-dev libtool libjansson-dev libmagic-dev git build-essential
# Extra for python
sudo pip install pydeep

# Setup tcpdump
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

# Setup user
sudo adduser $cuckoo_user
sudo usermod -a -G libvirtd $cuckoo_user

# Install Cuckoo
cd $cuckoo_path_base
git clone https://github.com/cuckoobox/cuckoo
cd cuckoo
sudo pip install -r requirements.txt
cd ..
sudo chown -R $cuckoo_user:$cuckoo_user cuckoo

# Install Yara and Yara Python
cd /tmp
wget https://github.com/plusvic/yara/archive/v3.4.0.tar.gz
tar -zxvf v3.4.0.tar.gz
cd yara-3.4.0
sh bootstrap.sh
./configure --enable-cuckoo --enable-magic
make
make install
cd yara-python
python setup.py build
sudo python setup.py install

# MongoDB Oficial
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 7F0CEB10
echo "deb http://repo.mongodb.org/apt/ubuntu "$(lsb_release -sc)"/mongodb-org/3.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-3.0.list
sudo apt-get update
sudo apt-get install -y mongodb-org
sudo sed -i 's/127\.0\.0\.1/0\.0\.0\.0/g' /etc/mongod.conf
sudo service mongodb restart


# install volatility
cd /tmp
wget https://github.com/volatilityfoundation/volatility/archive/2.5.tar.gz
tar -zxvf 2.5.tar.gz
cd volatility*
make
sudo make install
