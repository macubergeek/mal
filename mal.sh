#!/bin/bash
a=`cat <<-EOF
https://github.com/plusvic/yara.git
https://github.com/Yara-Rules/rules.git
https://github.com/volatilityfoundation/volatility.git
https://github.com/cuckoosandbox/community.git
https://github.com/cuckoosandbox/cuckoo.git
https://github.com/spender-sandbox/cuckoo-modified.git
https://github.com/buguroo/cuckooautoinstall.git
https://github.com/ChrisTruncer/Just-Metadata.git
https://github.com/buguroo/cuckooautoinstall.git
https://github.com/504ensicsLabs/DAMM.git
EOF`
cd /opt
for i in $a
do
git clone $i
done
wget http://digitalcorpora.org/downloads/bulk_extractor/bulk_extractor-1.5.5.tar.gz
