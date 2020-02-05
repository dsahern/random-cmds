#!/bin/bash
#
# pretty print device stats
#
# David Ahern <dsahern@gmail.com>

printf "%16s  %16s  %16s  %10s  %16s  %16s  %10s\n" \
	"Device" "Rx-bytes" "Rx-packets" "Rx-dropped" \
	"Device" "Tx-bytes" "Tx-packets" "Tx-dropped"

R=0
cat /proc/net/dev |
while read S;
do
	R=$((R+1))
	[ $R -lt 3 ] && continue;
	set -- $S
	DEV=${1}
	RXB=${2}
	RXP=${3}
	RD=${5}

	TXB=${10}
	TXP=${11}
	TD=${13}

	printf "%16s  %16s  %16s  %10s  %16s  %16s  %10s\n" \
		${DEV} ${RXB} ${RXP} ${RD} ${TXB} ${TXP} ${TD}
done
