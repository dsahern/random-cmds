#!/usr/bin/env python3
#
# Script to show ethtool stats for a netdev. Stat is expected to have
# the format rx[0-9]+_${stat} or tx[0-9]+_${stat}. Default stat is
# Rx packets.
#
# Script works for mlx5e stats

import os
import sys
import time
from datetime import datetime
import argparse
import subprocess
import re

stats_regex = re.compile(r'\d+')

# parse stats name and extract queue number. string is expected to
# have the format '[r,t]x[0-9]+_[a-z]*' and we extract the queue number
def get_qnum( name ):
    q = -1
    m = stats_regex.findall(name)
    if m:
        q = int(m[0])

    return q


# returns highest queue number seen in the stats output
def get_num_queue( cmd ):
    queue = 0
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    for line in p.stdout.readlines():
        # convert line as a byte stream to a string
        lstr = line.decode()
        lstr.strip()
        name, stat = lstr.split(":", 2)
        q = get_qnum(name)
        if q > queue:
            queue = q

    # number of queues is 1 + max; starts at 0
    return queue + 1


# run ethtool -S and save current value per queue
def read_stats( cmd ):
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    for line in p.stdout.readlines():
        lstr = line.decode()
        lstr.strip()
        name, stat = lstr.split(":", 2)
        q = get_qnum(name)
        curr[q] = int(stat)


################################################################################

def compute_delta( ):
    for q in range(nqueue):
        delta[q] = curr[q] - prev[q]


def rotate_data( ):
    for q in range(nqueue):
        prev[q] = curr[q]


def print_hdr( now ):
    os.system('clear')
    print("%s dev=%s stat=%s" % (now.strftime("%m/%d/%Y, %H:%M:%S"), dev, show_stat))

def print_stats( now ):
    print_hdr(now)
    for q in range(nqueue):
        if skip_zero == 0 or curr[q] > 0:
            print("%3u  %s" % (q, curr[q]))


def print_delta( now ):
    print_hdr(now)
    for q in range(nqueue):
        if skip_zero == 0 or delta[q] > 0:
            print("%3u  %10u" % (q, delta[q]))

################################################################################

dev = "eth0"
skip_zero = 0
show_delta = 0
direction = "rx"
stat = "packets"
dt = 1

parser = argparse.ArgumentParser()
parser.add_argument("--dev", type=str, nargs=1,
                    help='name of netdevice')
parser.add_argument("--rx-stat", type=str, nargs=1,
                    help='suffix in rx${queue}_${stat} of per-queue to show')
parser.add_argument("--tx-stat", type=str, nargs=1,
                    help='suffix in tx${queue}_${stat} of per-queue to show')
parser.add_argument("--delta", action='store_true',
                    help='show delta stats')
parser.add_argument("--skip-zero", action='store_true',
                    help='skip queue where stat is zero')
parser.add_argument("--dt", type=int, nargs=1,
                    help='sampling rate (default 1 sec)')
args = parser.parse_args()

if args.dev:
    dev = args.dev[0]

if args.rx_stat and args.tx_stat:
    print("Only 1 stat can be specified")
    exit(1)

if args.rx_stat:
    stat = args.rx_stat[0]

if args.tx_stat:
    stat = args.tx_stat[0]
    direction = "tx"

if args.delta:
    show_delta = 1

if args.skip_zero:
    skip_zero = 1

if args.dt:
    dt = args.dt[0]

show_stat = direction + "[0-9]+_" + stat
cmd = "ethtool -S " + dev + " | egrep '" + show_stat + "'"
nqueue = get_num_queue(cmd)

prev = [ 0 for i in range(nqueue) ]
curr = [ 0 for i in range(nqueue) ]
delta = [ 0 for i in range(nqueue) ]

read_stats(cmd)
rotate_data()
while 1:
    time.sleep(dt)
    now = datetime.now()

    read_stats(cmd)
    if show_delta == 0:
        print_stats(now)
    else:
        compute_delta()
        print_delta(now)
        rotate_data()

