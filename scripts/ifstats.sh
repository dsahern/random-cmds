#!/bin/bash
#
# pretty print rates for a netdev every second
#
# David Ahern <dsahern@gmail.com>

export LC_NUMERIC=""

DEV=${1}
[ -z $DEV ] && DEV=eth0
declare -i ITER=${2}

S=$(awk -v dev="${DEV}:" '$1 == dev {print}' /proc/net/dev)

set -- $S
RXB_P=${2}
RXP_P=${3}
RD_P=${5}

TXB_P=${10}
TXP_P=${11}
TD_P=${13}

sleep 1

printf "Stats for ${DEV}\n"
while [ 1 ]; do
	T=$(date +%T)
	S=$(awk -v dev="${DEV}:" '$1 == dev {print}' /proc/net/dev)

	set -- $S
	RXB=${2}
	RXP=${3}
	RD=${5}

	TXB=${10}
	TXP=${11}
	TD=${13}

	rbytes=$(($RXB - $RXB_P))
	rpkts=$(($RXP - $RXP_P))
	rdrop=$(($RD - $RD_P))
	if [ ${rpkts} -eq 0 ]; then
		rpktsz=0
	else
		rpktsz=$(($rbytes / $rpkts))
	fi

	tbytes=$(($TXB - $TXB_P))
	tpkts=$(($TXP - $TXP_P))
	tdrop=$(($TD - $TD_P))
	if [ ${tpkts} -eq 0 ]; then
		tpktsz=0
	else
		tpktsz=$(($tbytes / $tpkts))
	fi

	printf "$T "
	printf "Rx: %'11d   %'7d   %'5d   %'5d"   ${rbytes} ${rpkts} ${rpktsz} ${rdrop}
	printf "    "
	printf "Tx: %'11d   %'7d   %'5d   %'5d\n" ${tbytes} ${tpkts} ${tpktsz} ${tdrop}

	if [ ${ITER} -gt 0 ]; then
		ITER=$((ITER-1))
		[ ${ITER} -eq 0 ] && break
	fi
	sleep 1

	RD_P=$RD
	RXB_P=$RXB
	RXP_P=$RXP

	TD_P=$TD
	TXB_P=$TXB
	TXP_P=$TXP
done
