#!/bin/sh
set -e
set -x
wget https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/current/rds_modernm.zip
unzip rds_modernm.zip
python3 index.py rds_modernm/NSRLFile.txt NSRLFile.kct
