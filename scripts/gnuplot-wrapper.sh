#!/bin/sh

#set xdata time
#set timefmt "%m/%d/%Y %H:%M:%S"
#set format x "%d-%H:%M"
#set grid

usage() {
	echo "
usage: ${0##*/} -d data-filename -g graph-filename -t 'title'

where data-filename contains the data to be plotted and graph-filename is
the name of the file to write the generated picture.

The data file is assumed to have the format:
11/28/2007 09:52:12    2048248
where columns 1 and 2 are the date and time of the sample and column 3 is
what is to be plotted.
"
}

DATAFILE=
GRAPHFILE=
TITLE="-"

while getopts :d:g:t: o
do
    case $o in
		d) DATAFILE=$OPTARG;;
		g) GRAPHFILE=$OPTARG;;
		t) TITLE=$OPTARG;;
		*) usage; exit 1;;
	esac
done

if [ -z "$DATAFILE" -o -z "$GRAPHFILE" ]
then
	usage
	exit 1
fi


CMDFILE=$(mktemp /tmp/gplotcmd.XXXXXX)
echo "set terminal png
set xdata time
set timefmt \"%m/%d/%Y %H:%M:%S\"
set format x \"%d-%H:%M\"
set title \"$TITLE\"
set grid
plot \"$DATAFILE\" using 1:3 with lines
" >> $CMDFILE

echo "q" | gnuplot $CMDFILE - > $GRAPHFILE
