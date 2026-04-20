#!/bin/bash -x
#
# Configure subfunctions on a device. Assumes the mlxconfig or mlx5ctl
# command to enable SFs has already been run.

# need new devlink
PATH=/home/nvidia/dahern/bin:$PATH

function printhelp
{
	cat <<EOF
Usage: ${0##*/} OPTS

	-p id      PCI BDF in the format xxxx:xx:xx.x
	-s number  SF number to create

EOF
}

################################################################################
# main
#
# default device id
PDEV=0000:01:00.0

# default SF number to create
SFNUM=0

while getopts :p:s:h o
do
	case $o in
	p) PDEV=OPTARG;;
	s) SFNUM=$OPTARG;;
	h) printhelp;exit 0;;
	*) printhelp;exit 1;;
	esac
done

DEVNUM=$(echo ${PDEV} | awk -F ':' '{print $2}')
FNUM=$(echo ${PDEV} | awk -F ':' '{print $3}')
FNUM=$(printf "%02x" ${FNUM//*\./})

SFOCT=$(printf "%02x" ${SFNUM})
MAC=00:12:34:${DEVNUM}:${FNUM}:${SFOCT}

PDEV=pci/${PDEV}

# SFs require eswitch to be in switchdev mode
MODE=$(devlink dev eswitch show ${PDEV} -jp | jq '.dev.[].mode')
MODE=${MODE//\"}
if [ "${MODE}" != "switchdev" ]
then
	devlink dev eswitch set ${PDEV} mode switchdev
fi

# Add SF
SF_PDEV=$(devlink port add ${PDEV} flavour pcisf pfnum 0 sfnum ${SFNUM} | awk '{print $1; exit}')
SF_PDEV=${SF_PDEV%%:}
sleep 1

# Get netdev representer
devlink port show ${SF_PDEV}
NDEV_REP=$(devlink port show ${SF_PDEV} | awk '{print $5; exit}')

# set mac address and make representer active
devlink port function set ${NDEV_REP} hw_addr ${MAC} state active

while [ 1 ]
do
	devlink port show ${SF_PDEV} | grep -q "nested_devlink:"
	[ $? -eq 0 ] && break
	devlink port show ${SF_PDEV}
	sleep 1
done

# set driverinit parameters to get netdev and IB devices initialized
SF_ADEV=$(devlink port show ${SF_PDEV} | tail -1)
devlink dev param set ${SF_ADEV} name enable_eth value 1 cmode driverinit
devlink dev param set ${SF_ADEV} name enable_rdma value 1 cmode driverinit
devlink dev param set ${SF_ADEV} name enable_roce value 1 cmode driverinit
devlink dev reload ${SF_ADEV}
