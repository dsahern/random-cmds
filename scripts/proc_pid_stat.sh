#!/bin/bash 

# pretty print data in /proc/pid/stat

[ -z "$1" ] && echo "usage: ${0##*/} pid" >&2 && exit 1

[ ! -d "/proc/$1" ] && echo "\"$1\" is an invalid pid" >&2 && exit 2

# see fs/proc/array.c, do_task_stat()
#
# stime/utime are counts of USER_HZ (usually 100)

awk '
{
print "pid:                  ", $1
print "command:              ", $2
print "state:                ", $3
print "parent pid:           ", $4
print "process grp:          ", $5
print "session id:           ", $6
print "tty number:           ", $7
print "tty process group id: ", $8
printf "flags:                 0x%x\n", $9
print "minor faults:         ", $10
print "child minor faults:   ", $11
print "major faults:         ", $12
print "child major faults:   ", $13
print "user time (USER_HZ):  ", $14
print "sys time (USER_HZ):   ", $15
print "child user time:      ", $16
print "child system time:    ", $17
print "priority:             ", $18
print "nice:                 ", $19
print "number of threads:    ", $20
print "jiffies until timer:  ", $21
print "start time (jiffies): ", $22
print "virt mem size (bytes):", $23
print "rss (pages):          ", $24
print "rss limit (bytes):    ", $25
printf "start address - text:  0x%x\n", $26
printf "end address   - text:  0x%x\n", $27
printf "start address - stack: 0x%x\n", $28
printf "current stack pointer: 0x%x\n", $29
printf "current instruction p: 0x%x\n", $30
printf "pending signals:       0x%x\n", $31
printf "blocked signals:       0x%x\n", $32
printf "ignored signals:       0x%x\n", $33
printf "handled signals:       0x%x\n", $34
printf "wait address:          0x%x\n", $35
print "(should be 0):        ", $36
print "(should be 0):        ", $37
print "exit signal:          ", $38
print "processor last run on:", $39
print "real time priority:   ", $40
print "schedule policy:      ", $41
}
' /proc/$1/stat
