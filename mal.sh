#!/bin/bash
a=`cat <<-EOF
https://github.com/DidierStevens/DidierStevensSuite.git
https://github.com/plusvic/yara.git
https://github.com/buguroo/cuckooautoinstall.git
https://github.com/volatilityfoundation/volatility.git
https://github.com/Yara-Rules/rules.git
EOF`
cd /opt
for i in $a
do
git clone $i
done
#wget https://googledrive.com/host/0B6fULLT_NpxMQ1Rrb1drdW42SkE/remnux-6.0-ova-public.ova
apt-get update && apt-get upgrade && \
apt-get install git libssl-dev bison libjansson-dev
