#!/bin/bash
sudo apt-get install libtool flex autoconf libtool libjansson-dev libmagic-dev libssl-dev -y
cd /home/cuckoo/yara
sudo ./bootstrap.sh && \
sudo ./configure --enable-cuckoo --enable-magic
