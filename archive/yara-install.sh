#!/bin/bash
cd /yara
apt-get install autoconf libtool libjansson-dev libmagic-dev libssl-dev -y
sudo ./bootstrap.sh && ./configure --enable-cuckoo --enable-magic
sudo make
sudo make install
