#!/bin/bash

CMDSFILE=/tmp/gnuplot-cmds
PNGFILE=/tmp/out.png

COLX=1
COLY=2

usage()
{
	cat <<EOF
usage: ${0##*/} OPTS

OPTS:
	-f FILE     File to plot
	-X COL      Field in file to use for x-axis (default: ${COLX})
	-Y COL      Field in file to use for y-axis (default: ${COLY})
	-x x1:x2    X-range to use
	-y y1:y2    Y-range to use
	-s SEP      Column separator in file
EOF
}

################################################################################
# main
while getopts :f:x:y:X:Y:s: o
do
	case $o in
		f) FILE=$OPTARG;;
		s) SEP=$OPTARG;;
		x) XRANGE="[$OPTARG]";;
		y) YRANGE="[$OPTARG]";;
		X) COLX=$OPTARG;;
		Y) COLY=$OPTARG;;
		*) usage; exit 1;;
	esac
done

if [ -z "${FILE}" ]
then
	echo "Filename must be specified"
	usage
	exit 1
fi

#
# create commands file
#
echo "set terminal png enhanced size 640,480" > ${CMDSFILE}

if [ -n "${SEP}" ]
then
	echo "set datafile separator \"${SEP}\"" >> ${CMDSFILE}
fi

echo "set noautoscale" >> ${CMDSFILE}

if [ -n "${XRANGE}" ]
then
	echo "set xrange ${XRANGE}" >> ${CMDSFILE}
else
	echo "set autoscale x" >> ${CMDSFILE}
fi

if [ -n "${YRANGE}" ]
then
	echo "set yrange ${YRANGE}" >> ${CMDSFILE}
else
	echo "set autoscale y" >> ${CMDSFILE}
fi

echo "plot \"${FILE}\" using ${COLX}:${COLY} with lines" >> ${CMDSFILE}

echo "q" |  gnuplot ${CMDSFILE} - > ${PNGFILE}

#
# display using image magick
#
display-im6.q16 -nostdin ${PNGFILE}
