
CC = gcc
LD = ld
CFLAGS = -O2 -g -Wall
LDFLAGS = -static

all: rps pktgen

%: %.c
	$(CC) $(DEFS) $(CFLAGS) $(LDFLAGS) $< -o $@

clean:
	@rm -rf rps rps.o pktgen pktgen.o
