#!/bin/bash
#
# show the CPUs each mlx5 rx queue is handled on

printf "%8s %8s %8s\n" "queue" "irq" "cpu"
grep 'mlx5_comp' /proc/interrupts | \
while read irq line
do
	irq=${irq/:/}
	cpu=$(cat /proc/irq/${irq}/smp_affinity_list)
	q=${line/*mlx5_comp/}
	q=${q/@pci*/}

	printf "%8s %8s %8s\n" $q $irq $cpu
done
