#!/bin/bash
#
# show the CPUs each mlx5 rx queue is handled on

printf " cpu  MLX queue\n"
cat /proc/interrupts | \
awk '{
	if ($NF ~ /mlx5_comp/) {
		for (i = 2; i < NF-2; ++i) {
			if ($i != 0)
				printf " %3d", i - 2
		}
		printf "  %s\n", $NF
	}
}' | sort -k 1,1 -n
