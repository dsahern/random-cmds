#!/bin/bash
#
# Download qcow2 disk image from
#    http://cloud-images.ubuntu.com/releases
# and customize for local use.

# sane defaults
ROOTDIR=${HOME}/rootfs
FS_SHARE=${HOME}/rootfs
IMG=${IMG:-${HOME}/images/enf-vm.qcow2}

DEV=virtio
NCPUS=2
MEM=2048
KVER=
BIOSOPT=
MONPORT=7001

QEMU=qemu-system-x86_64
MACH="q35"

# bridge and VM connection for management network
# eth0 in VM <---> vm-tap <--> br0 <--> eth0 <--> WAN
HOSTDEV=br0
HOSTDEV2=br1

VMDEV=vm-tap
# last octet of mac address
MACLO=01  # $(printf "%02x" $((RANDOM & 255)))

################################################################################
# check host networking and configure if needed

config_host_net()
{
	local dev
	local addr
	local gw

	ip link sh dev ${HOSTDEV} >/dev/null 2>&1
	[ $? -eq 0 ] && return

	dev=$(ip ro ls default | awk '{print $5}')
	if [ -z "${dev}" ]
	then
		echo "Failed to find default networking device"
		return 1
	fi

	addr=$(ip -br -4 addr sh dev ${dev} | awk '{print $NF}')
	if [ -z "${addr}" ]
	then
		echo "Failed to find address of ${dev}"
		exit 1
	fi

	gw=$(ip ro ls default | awk '{print $3}')

	sudo ip li add ${HOSTDEV} type bridge
	sudo ip li set ${HOSTDEV} up

	# uncomment to make default NIC connected to bridge
	# sudo ip addr add dev ${HOSTDEV} ${addr}
	# sudo ip li set ${dev} master ${HOSTDEV}
	# sudo ip addr del dev ${dev} ${addr}
	# sudo ip ro add default via ${gw} dev ${HOSTDEV}

}

config_host_net2()
{
	[ -z "${VMDEV2}" ] && return

	ip link sh dev ${HOSTDEV2} >/dev/null 2>&1
	[ $? -eq 0 ] && return

	set -e
	sudo ip li add ${HOSTDEV2} type bridge
	sudo ip li set ${HOSTDEV2} up
	set +e
}

################################################################################
# configure vm networking

config_vm_net()
{
	sudo ip li del ${VMDEV} >/dev/null 2>&1
	sudo ip tuntap add mode tap dev ${VMDEV}
	sudo ip li set dev ${VMDEV} master ${HOSTDEV} up

	if [ -n "${VMDEV2}" ]
	then
		sudo ip li del ${VMDEV2} >/dev/null 2>&1
		sudo ip tuntap add mode tap dev ${VMDEV2}
		sudo ip li set dev ${VMDEV2} master ${HOSTDEV2} up
	fi
}

################################################################################
#
cleanup()
{
	stty "$STTY_SETTINGS"
	rm -f $TMPFILE
	sudo ip li del ${VMDEV} >/dev/null 2>&1
	[ -n "${VMDEV2}" ] && sudo ip li del ${VMDEV2} >/dev/null 2>&1
}

################################################################################
# help

usage()
{
	cat <<EOF
usage: ${0##*/} OPTS

options:
	-d DEV	  network device model (virtio, e1000, sfa; default: $DEV)
	-k KVER   kernel version (default: $KVER)
	-K KPATH  path to kernel files (default: $ROOTDIR)
	-i IMG    qcow2 disk image to use (default: $IMG)
	-c CPUS   number of cpus for VM (default: $NCPUS)
	-m MEM    amount of memory for VM (default: $MEM)
	-M MACH   machine type to use (default: ${MACH}; use ""
	          to use qemu's default; for options see '$QEMU -machine help')
	-q PATH   path to qemu-system-x86_64 binary to use (default: $QEMU)
	-9 PATH   use specified path for 9p sharing (default: ${FS_SHARE}, "" to disable)
	-L PATH   optional path to bios related files need for bootup. For eg. path to bios-256k.bin.
	-N name   add second network device with given name
	-S        Add shared memory device to VM

	-t dev    Device name to use for primary netdevice
	-T port   Port number to use for monitor
	-O mac    Last octet of mac address
EOF
}

################################################################################
# main

REBOOT=-no-reboot
IVM=

while getopts :k:K:d:c:m:q:i:9:M:L:St:T:O:rN: o
do
	case $o in
		k) KVER=$OPTARG;;
		K) ROOTDIR=$OPTARG;;
		d) DEV=$OPTARG;;
		c) NCPUS=$OPTARG;;
		m) MEM=$OPTARG;;
		M) MACH="$OPTARG";;
		N) VMDEV2="$OPTARG";;
		i) IMG=$OPTARG;;
		q) QEMU=$OPTARG;;
		9) FS_SHARE=$OPTARG;;
		L) BIOSOPT="-L $OPTARG";;
		S) IVM="-chardev socket,path=/tmp/ivshmem_socket,id=ivshmem_socket -device ivshmem-doorbell,vectors=64,chardev=ivshmem_socket";;
		#S) IVM="-device ivshmem-plain,memdev=hostmem -object memory-backend-file,size=64M,share,mem-path=/dev/shm/ahern,id=hostmem";;
		t) VMDEV=$OPTARG;;
		T) MONPORT=$OPTARG;;
		O) MACLO=$OPTARG;;
		r) REBOOT=;;
		*) usage; exit 1;;
	esac
done

# fixup user friendly device name with qemu device model name
case "$DEV" in
	virtio) DEV=virtio-net-pci;;
esac
if [ -n "${MACH}" ]
then
	MACH="-machine ${MACH}"
fi

config_host_net || exit 1
config_host_net2 || exit 1
config_vm_net   || exit 1

TMPFILE=$(mktemp /tmp/vm-start.XXXXXX)
trap 'cleanup' EXIT

cat >> $TMPFILE <<EOF
${QEMU} -m 2048 -smp ${NCPUS} -cpu host -enable-kvm ${REBOOT} -boot c         \\
    ${MACH} ${BIOSOPT} -serial stdio -nographic -monitor telnet::${MONPORT},server,nowait      \\
    -name ${USER}-vm,debug-threads=on  \\
    -drive file=${IMG},if=virtio,format=qcow2,cache=none                      \\
    ${IVM} \\
    -netdev type=tap,ifname=${VMDEV},script=no,downscript=no,id=netdev1       \\
    -device ${DEV},mac=52:54:00:12:34:${MACLO},netdev=netdev1,romfile=              \\
EOF

if [ -n "${VMDEV2}" ]
then
	cat >> ${TMPFILE} <<EOF
    -netdev type=tap,ifname=${VMDEV2},script=no,downscript=no,id=netdev2       \\
    -device ${DEV},mac=52:54:01:12:34:${MACLO},netdev=netdev2,romfile=              \\
EOF
fi

if [ -n "${FS_SHARE}" ]
then
	cat >> ${TMPFILE} <<EOF
    -fsdev local,security_model=none,id=fsdev0,path=${FS_SHARE}        \\
    -device virtio-9p-pci,id=fs0,fsdev=fsdev0,mount_tag=hostshare             \\
EOF
fi

if [ -n "${KVER}" ]
then
	cat >> ${TMPFILE} <<EOF
    -kernel ${ROOTDIR}/boot/vmlinuz-${KVER}                                   \\
    -append 'root=/dev/vda1 rootfs=ext4 ro console=ttyS0 net.ifnames=0 biosdevname=0 cma=256M' \\
EOF
fi

echo "" >> ${TMPFILE}

bash $TMPFILE
