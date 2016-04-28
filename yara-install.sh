#!/bin/bash
cd /opt/yara
sudo ./bootstrap.sh && ./configure --enable-cuckoo --enable-magic
