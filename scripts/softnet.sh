#!/bin/bash
#
# pretty print softnet_stat file
#
# from:
# https://raw.githubusercontent.com/majek/dump/master/how-to-receive-a-packet/softnet.sh

FILE=/proc/net/softnet_stat

cmd="${0##*/}"

usage() {
cat >&2 <<EOI
usage: $cmd [ -h ] [-f file]

	-f file     file to process, "-" = stdin
                    (default: /proc/net/softnet_stat)

Output column definitions:
      cpu  # of the cpu 

    total  # of packets (not including netpoll) received by the interrupt handler
             There might be some double counting going on:
                net/core/dev.c:1643: __get_cpu_var(netdev_rx_stat).total++;
                net/core/dev.c:1836: __get_cpu_var(netdev_rx_stat).total++;
             I think the intention was that these were originally on separate
             receive paths ... 

  dropped  # of packets that were dropped because netdev_max_backlog was exceeded

 squeezed  # of times ksoftirq ran out of netdev_budget or time slice with work
             remaining

collision  # of times that two cpus collided trying to get the device queue lock.

EOI
	exit 1
}



softnet_stats_header() {
	printf "%3s %10s %10s %10s %10s %10s %10s\n" cpu total dropped squeezed collision rps flow_limit
}

softnet_stats_format() {
	printf "%3u %10lu %10lu %10lu %10lu %10lu %10lu\n" "$1" "0x$2" "0x$3" "0x$4" "0x$5" "0x$6" "0x$7"
}

process_softnet()
{
	cpu=0

	while read total dropped squeezed j1 j2 j3 j4 j5 collision rps flow_limit_count
	do
		# the last field does not appear on older kernels
		# https://github.com/torvalds/linux/commit/99bbc70741903c063b3ccad90a3e06fc55df9245#diff-5dd540e75b320a50866267e9c52b3289R165
		softnet_stats_format $((cpu++)) "$total" "$dropped" "$squeezed" "$collision" "$rps" "${flow_limit_count:-0}"
	done
}

################################################################################
# main

while getopts :f:h o
do
	case $o in
	f) FILE=$OPTARG;;
	h) usage $0;exit 0;;
	*) usage $0;exit 1;;
	esac
done

softnet_stats_header

if [ ${FILE} = "-" ]; then
	process_softnet
else
	cat ${FILE} | process_softnet
fi
