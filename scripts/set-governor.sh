#!/bin/bash
#
# quick script to set CPU governor
#
# David Ahern <dsahern@gmail.com>

show_gov()
{
	local f

	find /sys/devices/system/cpu/cpufreq -name scaling_governor |
	while read f; do
		cat $f
	done
}

case $1 in
	perf*) gov=performance;;
	power*) gov=powersave;;
	show|stat|status) show_gov; exit 0;;
	*) echo "unknown governor"; exit 1;;
esac

find /sys/devices/system/cpu/cpufreq -name scaling_governor |
while read f; do
	c=$(cat $f)
	echo $gov > $f
	echo "$f: $c -> $gov"
done
