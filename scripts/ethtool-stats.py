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
from array import array

stats_regex = re.compile(r'\d+')
labels = {}

# parse stats name and extract queue number. string is expected to
# have the format '[r,t]x[0-9]+_[a-z]*' and we extract the queue number
def get_qnum( name ):
    q = 0
    m = stats_regex.findall(name)
    if m:
        q = int(m[0])

    return q


def get_label( name ):
    p,n = name.split('_', 1)
    return n


def get_col( name ):
    return int(labels[name])


# returns highest queue number seen in the stats output
def get_num_queue( cmd ):
    queue = 0
    col = 0
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    for line in p.stdout.readlines():
        # convert line as a byte stream to a string
        lstr = line.decode()
        lstr.strip()
        name, stat = lstr.split(":", 2)
        q = get_qnum(name)
        if q > queue:
            queue = q

        if q == 0:
            l = get_label(name)
            labels[l] = col
            col = col + 1

    # number of queues is 1 + max; starts at 0
    return queue + 1


# run ethtool -S and save current value per queue
def read_stats( cmd ):
    for q in range(nqueue):
        curr[q][ncols] = 0

    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    for line in p.stdout.readlines():
        lstr = line.decode()
        lstr.strip()
        name, stat = lstr.split(":", 2)
        q = get_qnum(name)
        l = get_label(name)
        j = get_col(l)
        curr[q][j] = int(stat)
        if curr[q][j] != 0:
            curr[q][ncols] = 1


################################################################################

def compute_delta( ):
    for q in range(nqueue):
        delta[q][ncols] = 0
        for j in range(ncols):
            delta[q][j] = curr[q][j] - prev[q][j]
            delta[q][ncols] += delta[q][j]


def rotate_data( ):
    for q in range(nqueue):
        for j in range(ncols):
            prev[q][j] = curr[q][j]


def print_timestamp( now ):
    if do_clear == 1:
        os.system('clear')
        print("%8s dev=%s stat=%s" % (now.strftime("%H:%M:%S"), dev, show_stat))
    else:
        print("%8s " % now.strftime("%H:%M:%S"), end='')

def print_hdr( ):
    if do_clear != 1:
        print("%8s " % "", end='')
    if qstats == 1:
        print("queue", end='')
    for k in labels.keys():
        print("  %16s" % k, end='')
    print("")


def print_stats( now ):
    for q in range(nqueue):
        if skip_zero == 0 or curr[q][ncols] > 0:
            print("%8s " % "", end='')
            if qstats == 1:
                print("%5u" % q, end='')

            for j in range(ncols):
                print("  %16u" % curr[q][j], end='')

            print("")


def print_delta( now ):
    nq = nqueue
    if qstats == 1:
        nq -= 1
        for j in range(ncols):
            delta[nqueue-1][j] = 0

    for q in range(nq):
        if skip_zero == 0 or delta[q][ncols] > 0:
            if q != 0:
                print("%8s " % "", end='')

            if qstats == 1:
                print("%5u" % q, end='')

            for j in range(ncols):
                if qstats == 1:
                    delta[nqueue-1][j] += delta[q][j]
                print("  %16u" % delta[q][j], end='')

            print("")

    if qstats == 1:
        print("%8s   sum" % "", end='')
        for j in range(ncols):
            print("  %16u" % delta[nqueue-1][j], end='')

        print("")

################################################################################

# defaults
dev = "eth0"
prefix="rx"
skip_zero = 0
show_delta = 0
dt = 1
do_clear = 1
qstats = 1

parser = argparse.ArgumentParser()
parser.add_argument("--dev", type=str, nargs=1,
                    help='name of netdevice')
parser.add_argument("--prefix", type=str, nargs=1,
                    help='prefix of per-queue to show')
parser.add_argument("--stat", type=str, nargs=1,
                    help='suffix in ${prefix}${queue}_${stat} of per-queue to show')
parser.add_argument("--nonq", type=str, nargs=1,
                    help='stats to show')
parser.add_argument("--delta", action='store_true',
                    help='show delta stats')
parser.add_argument("--skip-zero", action='store_true',
                    help='skip queue where stat is zero')
parser.add_argument("--dt", type=int, nargs=1,
                    help='sampling rate (default 1 sec)')
parser.add_argument("--noclear", action='store_true',
                    help='do not clear screen between samples')
args = parser.parse_args()

if args.dev:
    dev = args.dev[0]

nstat = 0
if args.noclear:
    do_clear = 0

if args.prefix:
    prefix = args.prefix[0]

if args.stat:
    nstat += 1
    stat = args.stat[0]
    show_stat = prefix + "[0-9]+_" + stat
    cmd = "ethtool -S " + dev + " | egrep '" + show_stat + "'"

if args.nonq:
    qstats = 0
    nstat += 1
    show_stat = args.nonq[0]
    cmd = "ethtool -S " + dev + " | egrep '" + show_stat + "'"

if nstat > 1:
    print("Only 1 stat group can be specified")
    exit(1)

if nstat == 0:
    if args.prefix:
        show_stat = prefix + "[0-9]+_"
    else:
        show_stat = prefix + "[0-9]+_packets|" + prefix + "[0-9]+_bytes"

    cmd = "ethtool -S " + dev + " | egrep '" + show_stat + "'"

if args.delta:
    show_delta = 1

if args.skip_zero:
    skip_zero = 1

if args.dt:
    dt = args.dt[0]

nqueue = get_num_queue(cmd)
ncols = len(labels)

# add 1 for a sum row
if qstats == 1 and show_delta == 1:
    nqueue = nqueue + 1

prev  = [ [0 for i in range(ncols + 1)] for j in range(nqueue) ]
curr  = [ [0 for i in range(ncols + 1)] for j in range(nqueue) ]
delta = [ [0 for i in range(ncols + 1)] for j in range(nqueue) ]

n = 0

if do_clear == 0:
    print_hdr()

read_stats(cmd)
rotate_data()

while 1:
    time.sleep(dt)
    now = datetime.now()

    read_stats(cmd)

    if do_clear == 0:
        n = n + 1
        if n == 16:
            print_hdr()
            n = 0

    print_timestamp( now )

    if do_clear == 1:
        print_hdr()

    if show_delta == 0:
        print_stats(now)
    else:
        compute_delta()
        print_delta(now)
        rotate_data()

