#!/bin/bash

### Needs "PyAsn", install using "pip install pyasn"
### pyasn_util commands will be installed in /usr/local/bin

cd /etc/unbound

rm -f rib.*.bz2 ipasn.dat

pyasn_util_download.py --latestv46

FILE=`ls -1At rib.*.bz2`

pyasn_util_convert.py --single ${FILE} ipasn.dat

pyasn_util_asnames.py | grep -oE "\"[0-9]+\":[[:blank:]]*\"[^\"]+\"" | sed "s/\"//g" | sed "s/^\([0-9]*\): /\1\t/g" | sort -k1,1g > asnnames.dat

echo "Done!"

exit 0

