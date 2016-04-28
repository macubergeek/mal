#!/bin/bash
cd /opt/yara
apt-get install autoconf libtool libjansson-dev libmagic-dev libssl-dev -y
sudo ./bootstrap.sh && ./configure --enable-cuckoo --enable-magic && \
cd /opt/yara/yara-python && \
python setup.py build && \
python setup.py install && \
yara -v
pip show yara-python
