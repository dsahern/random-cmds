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
	-c COL      Field in file to use for y-axis (default: ${COLY})
	-C COL      Field in file to use for x-axis (default: ${COLX})
	-X label    Label for x-axis
	-Y label    Label for y-axis
	-x x1:x2    X-range to use
	-y y1:y2    Y-range to use
	-t fmt      X is time with format "fmt"
	-s SEP      Column separator in file
EOF
}

################################################################################
# main

XLABEL=
YLABEL=

while getopts :f:x:y:c:C:s:o:t:X:Y: o
do
	case $o in
		c) COLY=$OPTARG;;
		C) COLX=$OPTARG;;
		f) FILE=$OPTARG;;
		o) PNGFILE=$OPTARG;;
		s) SEP=$OPTARG;;
		t) FMT=$OPTARG;;
		x) XRANGE="[$OPTARG]";;
		y) YRANGE="[$OPTARG]";;
		X) XLABEL=$OPTARG;;
		Y) YLABEL=$OPTARG;;
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

echo "set key off" >> ${CMDSFILE}

if [ -n "${XRANGE}" ]
then
	echo "set xrange ${XRANGE}" >> ${CMDSFILE}
else
	echo "set autoscale x" >> ${CMDSFILE}
fi

if [ -n "${XLABEL}" ]
then
	echo "set xlabel \"${XLABEL}\"" >> ${CMDSFILE}
fi

if [ -n "${FMT}" ]
then
	echo "set  xdata time"  >> ${CMDSFILE}
	echo "set timefmt \"${FMT}\""  >> ${CMDSFILE}
fi

if [ -n "${YRANGE}" ]
then
	echo "set yrange ${YRANGE}" >> ${CMDSFILE}
else
	echo "set autoscale y" >> ${CMDSFILE}
fi

if [ -n "${YLABEL}" ]
then
	echo "set ylabel \"${YLABEL}\"" >> ${CMDSFILE}
fi

echo "set output \"${PNGFILE}\"" >> ${CMDSFILE}
echo "set grid" >> ${CMDSFILE}

echo "plot \"${FILE}\" using ${COLX}:${COLY} with lines" >> ${CMDSFILE}

echo "q" |  gnuplot ${CMDSFILE}
[ $? -ne 0 ] && exit 1

#
# display using image magick
#
display-im6.q16 -nostdin ${PNGFILE}
