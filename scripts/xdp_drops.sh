#!/bin/bash
#
# Similar to ethq but for XDP drops
#
# David Ahern <dsahern@gmail.com>

export LC_NUMERIC=""

# expects XDP stats to be available via ethtool -S and contain
# 'xdp_drop'. Works for virtio_net

get_xdp_drops()
{
	local dev=$1

	ethtool -S $dev |\
	awk '{ if ($1 ~ "xdp_drop") sum += $2 } END {print sum}'
}

DEV=eth0
[ -n "$1" ] && DEV=${1}

DT=1
[ -n "$2" ] && DT=${2}

# previous count
N_P=$(get_xdp_drops ${DEV})
sleep ${DT}

while [ 1 ]
do
	T=$(date +%T)
	N=$(get_xdp_drops ${DEV})
	printf "%s: %'6d\n" ${T} $((N - N_P))
	N_P=${N}
	sleep ${DT}
done
