#!/bin/bash
## Purpose of script is to do initial information grab from memory dump.
## Use in conjunction with volatilityrc file, to store volatility configs.
## Move volatilityrc to .volatilityrc in investigation folder.
a=`cat <<-EOF
imageinfo
kdbgscan
pslist
psscan
psxview
pstree
dlllist
cmdline
handles
privs
getsids
envars
consoles
svcscan
connections
sockets
connscan
sockscan
netscan
modules
modscan
callbacks
mutantscan
hivelist
clipboard
messagehooks
EOF`
cd ../ 
for i in $a
do
vol.py $i >> $i.txt
done