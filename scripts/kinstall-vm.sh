#!/bin/bash

BLDDIR=vm-kbuild
ROOTDIR=${HOME}/rootfs
IMG=${HOME}/ubuntu-20.04-server-cloudimg-amd64-disk-kvm.img

usage()
{
        cat <<EOF
usage: ${0##*/} OPTS

    -b dir       build directory (default: $BLDDIR)
    -r dir       Root directory for install (default: $ROOTDIR)
    -s           Start VM with new kernel
EOF
}

################################################################################
# main

LAUNCH_VM=no

while getopts :b:r:s o
do
        case $o in
                b) BLDDIR=$OPTARG;;
                r) ROOTDIR=$OPTARG;;
                s) LAUNCH_VM=yes;;
                *) usage; exit 1;;
        esac
done

if [ ! -d ${ROOTDIR} ]; then
	echo "$ROOTDIR does not exist; mounted?"
	exit 1
fi

set -e
KVER=$(cat ${BLDDIR}/include/config/kernel.release)
/bin/rm -rf ${ROOTDIR}/lib/modules/${KVER}

mkdir -p ${ROOTDIR}/boot
/bin/rm -f ${ROOTDIR}/boot/vmlinuz-${KVER} ${ROOTDIR}/boot/System.map-${KVER} ${ROOTDIR}/boot/config-${KVER}
/bin/cp ${BLDDIR}/arch/x86/boot/bzImage ${ROOTDIR}/boot/vmlinuz-${KVER}
/bin/cp ${BLDDIR}/System.map ${ROOTDIR}/boot/System.map-${KVER}
/bin/cp ${BLDDIR}/.config ${ROOTDIR}/boot/config-${KVER}
/bin/cp ${BLDDIR}/vmlinux ${ROOTDIR}/boot/vmlinux-${KVER}

make  INSTALL_MOD_PATH=${ROOTDIR} O=${BLDDIR} modules_install

if [ ${LAUNCH_VM} = "yes" ];
then
	${HOME}/bin/vm-start.sh ${KVER}
fi
