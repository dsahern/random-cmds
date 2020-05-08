#!/bin/bash
#
# show the CPUs each mlx5 rx queue is handled on

cat /proc/interrupts | \
awk '{
	if ($NF ~ /mlx5_comp/) {
		printf $NF
		for (i = 2; i < NF-3; ++i) {
			if ($i != 0)
				printf " " i - 2
		}
		printf "\n"}
}' | sort -k 1,1
