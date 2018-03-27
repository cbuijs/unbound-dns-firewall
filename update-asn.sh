#!/bin/bash

### Needs "PyAsn", install using "pip install pyasn"
### pyasn_util commands will be installed in /usr/local/bin

cd /etc/unbound

rm -f rib.*.bz2 ipasn.dat

pyasn_util_download.py --latestv46

FILE=`ls -1At rib.*.bz2`

pyasn_util_convert.py --single ${FILE} ipasn.dat

echo "Done!"

exit 0

