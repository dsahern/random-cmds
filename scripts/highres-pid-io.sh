#!/bin/bash

# "time,kB_rd/s,kB_wr/s,kB_ccwr/s,iodelay"
#sudo  pidstat -C qemu-system-x86 -d 10

sudo  pidstat -d 1 | awk '$3 != "UID" && ($5 > 1000.0 || $6 > 1000.0 || $8 > 5) {print}' | gzip > qemu-io-stats.$(date +%s).gz
