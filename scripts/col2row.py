#!/usr/bin/env python3
#
# Flip rows and columns in a file

import argparse
import fileinput

num_row=200
num_col=200

parser = argparse.ArgumentParser()
parser.add_argument("--rows", type=int, nargs=1,
                    help='number of rows')
parser.add_argument("--cols", type=int, nargs=1,
                    help='number of columns')
parser.add_argument("--file", type=str, nargs=1,
                    help='file to parse')

args = parser.parse_args()
if args.rows:
    num_row=args.rows[0]

if args.cols:
    num_row=args.cols[0]

if args.file:
    fname = args.file[0]
    f = open(fname, 'r')
else:
    f = fileinput.input()

d = [ [ "" for i in range(num_row) ] for j in range(num_col) ]

j = 0
imax = 0
for line in f:
    t = line.split()

    k = len(t)
    if k > imax:
        imax = k

    for i in range(k):
        d[i][j] = t[i]

    j += 1

jmax = j
for i in range(imax):
    for j in range(jmax):
        print("%20s " % d[i][j], end='')

    print("")
