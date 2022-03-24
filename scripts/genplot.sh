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
	-o PNG      Output file to write png image (default: ${PNGFILE})
	-X COL      Field in file to use for x-axis (default: ${COLX})
	-Y COL      Field in file to use for y-axis (default: ${COLY})
	-x x1:x2    X-range to use
	-y y1:y2    Y-range to use
	-s SEP      Column separator in file
EOF
}

################################################################################
# main
while getopts :f:x:y:X:Y:s:o: o
do
	case $o in
		f) FILE=$OPTARG;;
		o) PNGFILE=$OPTARG;;
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
echo "set terminal png enhanced size 1024,768" > ${CMDSFILE}

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

echo "set output \"${PNGFILE}\"" >> ${CMDSFILE}

echo "plot \"${FILE}\" using ${COLX}:${COLY} with lines" >> ${CMDSFILE}

echo "q" |  gnuplot ${CMDSFILE}
[ $? -ne 0 ] && exit 1

#
# display using image magick
#
display-im6.q16 -nostdin ${PNGFILE}
