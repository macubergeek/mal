#!/bin/bash
sudo apt-get install subversion pcregrep libpcre++-dev python-dev -y
sudo apt-get install python-pip
sudo git clone https://github.com/gdabah/distorm.git
cd distorm
sudo python setup.py build
sudo python setup.py build install
cd .. && \
sudo make && sudo make install
