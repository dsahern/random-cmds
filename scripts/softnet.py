#!/usr/bin/env python3
#
# monitor /proc/net/softnet_stat file
# fields: total dropped squeezed - - - - - collision rps flow_limit_count

import os
import sys
import time
from datetime import datetime
import multiprocessing
import argparse

ncpu = multiprocessing.cpu_count()

prev = [ [0 for i in range(6)] for j in range(ncpu) ]
curr = [ [0 for i in range(6)] for j in range(ncpu) ]
delta = [ [0 for i in range(7)] for j in range(ncpu) ]

def read_softnet( f ):
    cpu = 0
    for line in f:
        tot, dro, squ, j1, j2, j3, j4, j5, col, rps, flo = line.split(" ")[0:11]

        curr[cpu][0] = int(tot, 16)
        curr[cpu][1] = int(dro, 16)
        curr[cpu][2] = int(squ, 16)
        curr[cpu][3] = int(col, 16)
        curr[cpu][4] = int(rps, 16)
        curr[cpu][5] = int(flo, 16)

        cpu = cpu + 1

    f.seek(0)

def compute_delta( ):
    for cpu in range(ncpu):
        delta[cpu][6] = 0
        for j in range(6):
            delta[cpu][j] = curr[cpu][j] - prev[cpu][j]
            delta[cpu][6] += delta[cpu][j]


def rotate_data( ):
    for cpu in range(ncpu):
        for j in range(6):
            prev[cpu][j] = curr[cpu][j]


def print_softnet( now ):
    if do_clear == 1:
        os.system('clear')

    print("%s" % (now.strftime("%m/%d/%Y, %H:%M:%S")))
    print("%3s  %10s  %10s  %10s  %10s  %10s" % \
          ("cpu", "total", "dropped", "squeezed", "rps", "flow_lmt"))
    for cpu in range(ncpu):
        print("%3u  %10u  %10u  %10u  %10u  %10u" % \
          (cpu, curr[cpu][0], curr[cpu][1], curr[cpu][2], curr[cpu][4], curr[cpu][5]))


def print_delta( now ):
    if do_clear == 1:
        os.system('clear')

    print("\n%s" % (now.strftime("%m/%d/%Y, %H:%M:%S")))
    print("%3s  %10s  %10s  %10s  %10s  %10s" % \
          ("cpu", "total", "dropped", "squeezed", "rps", "flow_lmt"))

    for cpu in range(ncpu):
        if skip_zero == 0:
            delta[cpu][6] = 1
        if delta[cpu][6] > 0:
            print("%3u  %10u  %10u  %10u  %10u  %10u" % \
                  (cpu, delta[cpu][0], delta[cpu][1], delta[cpu][2], delta[cpu][4], delta[cpu][5]))


def print_delta_cpu(cpu, now):
    print("%10s %3u  %10u  %10u  %10u  %10u  %10u" % \
          (now.strftime("%H:%M:%S"), cpu, delta[cpu][0], delta[cpu][1],\
           delta[cpu][2], delta[cpu][4], delta[cpu][5]))


################################################################################

skip_zero = 0
show_delta = 0
show_cpu = -1
do_clear = 1
dt = 1

parser = argparse.ArgumentParser()
parser.add_argument("--cpu", type=int, nargs=1,
                    help='show stats only for this cpu')
parser.add_argument("--delta", action='store_true',
                    help='show delta stats')
parser.add_argument("--skip-zero", action='store_true',
                    help='skip zero rows')
parser.add_argument("--dt", type=int, nargs=1,
                    help='sampling rate (default 1 sec)')
parser.add_argument("--noclear", action='store_true',
                    help='do not clear screen between samples')
args = parser.parse_args()

if args.cpu:
    cpu = args.cpu[0]
    if cpu >= 0:
        if cpu > ncpu:
            print("Invalid cpu. max is %u" % ncpu)
            sys.exit(1)

        show_cpu = cpu

if args.delta:
    show_delta = 1

if args.skip_zero:
    skip_zero = 1

if args.dt:
    dt = args.dt[0]

if args.noclear:
    do_clear = 0

f = open('/proc/net/softnet_stat', 'r')

read_softnet(f)
rotate_data()
while 1:
    time.sleep(dt)
    now = datetime.now()

    read_softnet(f)
    if show_delta == 0:
        print_softnet(now)
    else:
        compute_delta()
        if show_cpu < 0:
            print_delta(now)
        else:
            print_delta_cpu(show_cpu, now)

        rotate_data()

f.close()
