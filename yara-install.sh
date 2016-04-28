#!/bin/bash
cd /home/cuckoo/yara
apt-get install autoconf libtool libjansson-dev libmagic-dev libssl-dev -y
sudo ./bootstrap.sh && ./configure --enable-cuckoo --enable-magic && \
cd /home/cuckoo/yara/ && \
python setup.py build && \
python setup.py install && \
yara -v
pip show yara-python
